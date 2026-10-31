package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256" // [H2] 密码哈希
	"crypto/subtle" // [H2/H3] 恒定时间比较,防时序攻击
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// 北京时区 (UTC+8)
var cstZone = time.FixedZone("CST", 8*3600)

// ===== 日志内存缓冲区 =====
type LogMemory struct {
	mu   sync.Mutex
	logs []string
	max  int
}

func NewLogMemory(maxLines int) *LogMemory {
	return &LogMemory{logs: make([]string, 0, maxLines), max: maxLines}
}

func (l *LogMemory) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	line := strings.TrimSpace(string(p))
	if line != "" {
		if len(l.logs) >= l.max {
			l.logs = l.logs[1:]
		}
		l.logs = append(l.logs, fmt.Sprintf("[%s] %s", time.Now().In(cstZone).Format("15:04:05"), line))
	}
	l.mu.Unlock()
	return os.Stdout.Write(p)
}

func (l *LogMemory) GetLogs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := make([]string, len(l.logs))
	copy(result, l.logs)
	return result
}

var logBuf = NewLogMemory(100)

// ===== 配置与监控状态 =====
type Config struct {
	IntervalMinutes int    `json:"interval_minutes"`
	NotifyType      string `json:"notify_type"`
	SMTPHost        string `json:"smtp_host"`
	SMTPPort        string `json:"smtp_port"`
	SMTPUser        string `json:"smtp_user"`
	SMTPPass        string `json:"smtp_pass"`
	SenderName      string `json:"sender_name"` // 发件人名称
	ToEmail         string `json:"to_email"`
	WebhookURL      string `json:"webhook_url"`
	AuthUser        string `json:"auth_user"` // 登录账号
	AuthPass         string `json:"auth_pass"`          // 登录密码
	LoginExpireHours int    `json:"login_expire_hours"` // 登录有效期(小时)
	SessionVersion   int    `json:"session_version"`   // [M4] 会话版本号,改密时递增使所有旧会话失效,持久化到 config.json 确保重启后仍生效
}

type Status struct {
	LastIP     string `json:"last_ip"`
	QueryTime  int64  `json:"query_time_ms"` // 查询耗时(毫秒)
	LastCheck  string `json:"last_check"`    // 最后检查时间
	UsedSource string `json:"used_source"`   // 成功的接口
}

var (
	config     Config
	status     Status
	dataLock   sync.Mutex
	configFile = "/data/config.json"
)

func loadConfig() {
	dataLock.Lock()
	defer dataLock.Unlock()
	file, err := os.ReadFile(configFile)
	if err == nil {
		if uerr := json.Unmarshal(file, &config); uerr != nil {
			log.Printf("[L6] 配置文件解析失败,使用默认配置: %v", uerr) // [L6] 配置错误记日志
		}
	} else {
		config = Config{IntervalMinutes: 2, NotifyType: "email"}
	}
	// [H1] 鉴权字段为空时:用户名默认 admin,密码用 crypto/rand 随机生成(不再使用弱默认密码)
	// 随机密码仅打印到容器标准输出(不进 Web 日志),首次登录后请立即修改
	changed := false
	if config.AuthUser == "" {
		config.AuthUser = "admin"
		changed = true
	}
	if config.AuthPass == "" {
		rawPwd := make([]byte, 12)
		if _, err := rand.Read(rawPwd); err != nil {
			log.Fatalf("[H1] 生成随机密码失败: %v", err)
		}
		randomPwd := hex.EncodeToString(rawPwd)
		fmt.Println("========================================")
		fmt.Printf("[安全提示] 首次运行已生成随机登录密码\n")
		fmt.Printf("账号: %s  密码: %s\n", config.AuthUser, randomPwd)
		fmt.Println("请立即登录并修改密码,此密码仅显示一次")
		fmt.Println("========================================")
		config.AuthPass = hashPassword(randomPwd) // [H2] 密码以哈希存储
		changed = true
	} else if !isHashedPassword(config.AuthPass) {
		// [H2] 兼容旧版明文密码:首次加载时自动迁移为哈希格式,用户原密码不受影响
		config.AuthPass = hashPassword(config.AuthPass)
		changed = true
	}
	// 登录有效期缺失或非法(<=0)时设默认 24 小时，并随默认配置持久化
	if config.LoginExpireHours <= 0 {
		config.LoginExpireHours = 24
		changed = true
	}
	if changed {
		saveConfigToFile(config)
	}
}

// saveConfigToFile 将配置写入文件（调用方需自行持有 dataLock，避免重复加锁死锁）
// [M11] 配置含 SMTP 密码等敏感信息,文件权限收紧为仅属主可读写(0600)
func saveConfigToFile(cfg Config) error {
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.MkdirAll("/data", 0755)
	return os.WriteFile(configFile, data, 0600)
}

// ===== [H2] 密码哈希(标准库实现,保持零第三方依赖) =====
// 存储格式: sha256$<hex salt>$<hex hash>,与旧版明文密码向后兼容

// [I1] hashIterations 密码哈希迭代拉伸次数:单轮 SHA-256 过快,离线爆破成本低,
// 迭代 10000 次显著提高攻击成本,同时登录频率低、性能开销可接受
const hashIterations = 10000

// isHashedPassword 判断存储值是否为哈希格式(sha256$salt$hash)
func isHashedPassword(s string) bool {
	return strings.HasPrefix(s, "sha256$") && strings.Count(s, "$") == 2
}

// hashPassword 使用 SHA-256 + 随机 salt 对密码哈希
// [I1] 迭代拉伸 hashIterations 次;格式保持 sha256$salt$hash 向后兼容
func hashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		// rand 失败极少见,以时间戳兜底保证可用性
		salt = []byte(fmt.Sprintf("%x", time.Now().UnixNano()))
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(password))
	sum := h.Sum(nil)
	// [I1] 首轮结果与旧单轮哈希一致,后续继续迭代拉伸
	for i := 0; i < hashIterations-1; i++ {
		h.Reset()
		h.Write(sum)
		sum = h.Sum(nil)
	}
	return fmt.Sprintf("sha256$%s$%s", hex.EncodeToString(salt), hex.EncodeToString(sum))
}

// verifyPassword 校验密码,使用 subtle.ConstantTimeCompare 防止时序攻击
// 兼容旧版明文密码与旧单轮哈希;[I1] 新哈希为迭代拉伸格式
func verifyPassword(stored, input string) bool {
	if !isHashedPassword(stored) {
		// 旧版明文密码:恒定时间比较
		return subtle.ConstantTimeCompare([]byte(stored), []byte(input)) == 1
	}
	parts := strings.Split(stored, "$")
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	wantHash, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(input))
	sum := h.Sum(nil)
	// [I1] 兼容旧单轮哈希(首轮结果即旧格式)
	if subtle.ConstantTimeCompare(sum, wantHash) == 1 {
		return true
	}
	// [I1] 继续迭代拉伸,校验新格式
	for i := 0; i < hashIterations-1; i++ {
		h.Reset()
		h.Write(sum)
		sum = h.Sum(nil)
	}
	return subtle.ConstantTimeCompare(sum, wantHash) == 1
}

// [I1] isLegacySingleRoundHash 判断存储哈希是否为旧单轮格式(需升级为迭代哈希)
// 登录成功后调用,为 true 时用 hashPassword 重新存储完成升级
func isLegacySingleRoundHash(stored, input string) bool {
	if !isHashedPassword(stored) {
		return false
	}
	parts := strings.Split(stored, "$")
	salt, err := hex.DecodeString(parts[1])
	if err != nil {
		return false
	}
	wantHash, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(input))
	return subtle.ConstantTimeCompare(h.Sum(nil), wantHash) == 1
}

func saveConfig(newCfg Config) error {
	dataLock.Lock()
	defer dataLock.Unlock()
	config = newCfg
	return saveConfigToFile(config)
}

// ===== Session 管理与登录鉴权 =====
// [H3] session 携带 CSRF token,所有状态变更请求须校验,防范跨站请求伪造
type sessionData struct {
	expiry time.Time
	csrf      string    // 与该会话绑定的 CSRF token
	version   int       // [M4] 创建该会话时的会话版本号,与当前版本不一致则失效
	createdAt time.Time // [L5] 会话创建时间,超限时用于淘汰最早创建的会话
}

var (
	sessions   = make(map[string]sessionData) // token -> 会话数据
	sessionMux sync.Mutex
)

// [L5] MaxSessions 最大并发会话数上限,防止 sessions map 被无限撑大耗尽内存
const MaxSessions = 1000

// [M4] getSessionVersion 读取当前会话版本号(每次修改密码时递增,用于失效所有旧会话)
func getSessionVersion() int {
	dataLock.Lock()
	defer dataLock.Unlock()
	return config.SessionVersion
}

// getSessionTimeout 读取配置中的登录有效期（持有 dataLock 保护，避免与 saveConfig 并发竞争）
// 配置缺失或非法(<=0)时兜底为 24 小时
func getSessionTimeout() time.Duration {
	dataLock.Lock()
	hours := config.LoginExpireHours
	dataLock.Unlock()
	if hours <= 0 {
		hours = 24
	}
	return time.Duration(hours) * time.Hour
}

// createSession 生成 32 字节随机 hex token 及配套 CSRF token
// Cookie 为会话级（不设 MaxAge，关闭浏览器即登出）；未关闭窗口时由服务端 session 按配置有效期自动过期（滑动续期）
func createSession() (string, string) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// 极少发生，使用时间戳兜底
		return fmt.Sprintf("%x", time.Now().UnixNano()), fmt.Sprintf("%x", time.Now().UnixNano()+1)
	}
	token := hex.EncodeToString(b)
	csrfB := make([]byte, 32)
	// [L8] 检查 rand.Read 错误:失败时若静默继续,csrfB 全零导致 CSRF token 可预测;
	// 此处记录日志并以时间戳兜底(与 session token 兜底策略一致),保证 token 非空
	var csrf string
	if _, err := rand.Read(csrfB); err != nil {
		log.Printf("[L8] 生成 CSRF 随机数失败,已用时间戳兜底: %v", err)
		csrf = fmt.Sprintf("%x", time.Now().UnixNano())
	} else {
		csrf = hex.EncodeToString(csrfB)
	}
	// [M4] 记录当前会话版本号,改密递增版本后旧版本会话自动失效
	// [L5] 记录创建时间,超限淘汰最早会话;在 sessionMux 外读取版本/超时,避免持 sessionMux 时获取 dataLock
	ver := getSessionVersion()
	timeout := getSessionTimeout()
	now := time.Now()
	sessionMux.Lock()
	sessions[token] = sessionData{
		expiry:    now.Add(timeout),
		csrf:      csrf,
		version:   ver,
		createdAt: now,
	}
	// [L5] 会话数量上限:超限时先清理已过期会话,仍超限则淘汰最早创建的会话
	if len(sessions) > MaxSessions {
		for t, d := range sessions {
			if now.After(d.expiry) {
				delete(sessions, t)
			}
		}
		for len(sessions) > MaxSessions {
			var oldestToken string
			var oldestCreated time.Time
			first := true
			for t, d := range sessions {
				if first || d.createdAt.Before(oldestCreated) {
					oldestToken = t
					oldestCreated = d.createdAt
					first = false
				}
			}
			if oldestToken == "" {
				break
			}
			delete(sessions, oldestToken)
		}
	}
	sessionMux.Unlock()
	return token, csrf
}

// isValidSession 校验 session 是否存在且未过期，过期则删除；校验通过时滑动续期
func isValidSession(token string) bool {
	// [M4] 先在 sessionMux 外读取当前会话版本号与超时配置,避免持 sessionMux 时获取 dataLock
	curVer := getSessionVersion()
	timeout := getSessionTimeout()
	if token == "" {
		return false
	}
	sessionMux.Lock()
	defer sessionMux.Unlock()
	data, ok := sessions[token]
	if !ok {
		return false
	}
	// [M4] 会话版本与当前版本不一致(密码已修改)则删除该会话,要求重新登录
	if data.version != curVer {
		delete(sessions, token)
		return false
	}
	if time.Now().After(data.expiry) {
		delete(sessions, token)
		return false
	}
	// 滑动续期：校验通过即刷新闲置过期时间，浏览器保持打开期间不会过期;保留 version 与 createdAt
	sessions[token] = sessionData{
		expiry:    time.Now().Add(timeout),
		csrf:      data.csrf,
		version:   data.version,
		createdAt: data.createdAt,
	}
	return true
}

// [H3] getCSRFToken 返回指定会话的 CSRF token;会话无效返回空
// [L7] 增校验 SessionVersion:改密后版本过期会话不再发放 CSRF,防止旧会话仍可取 token 发起状态变更
func getCSRFToken(token string) string {
	// [L7] 先在 sessionMux 外读取当前会话版本号,避免持 sessionMux 时获取 dataLock(与 isValidSession 同序)
	curVer := getSessionVersion()
	sessionMux.Lock()
	defer sessionMux.Unlock()
	data, ok := sessions[token]
	if !ok || time.Now().After(data.expiry) {
		return ""
	}
	// [L7] 会话版本与当前不一致(密码已修改)则视为无效,不返回 CSRF token
	if data.version != curVer {
		return ""
	}
	return data.csrf
}

// [H3] validateCSRF 校验请求中的 CSRF token 与会话绑定 token 是否一致(恒定时间比较)
// 表单字段 csrf_token 或请求头 X-CSRF-Token 均可
func validateCSRF(r *http.Request) bool {
	cookie, err := r.Cookie("session_token")
	if err != nil {
		return false
	}
	want := getCSRFToken(cookie.Value)
	if want == "" {
		return false
	}
	got := r.FormValue("csrf_token")
	if got == "" {
		got = r.Header.Get("X-CSRF-Token")
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

// deleteSession 删除指定 session
func deleteSession(token string) {
	sessionMux.Lock()
	delete(sessions, token)
	sessionMux.Unlock()
}

// cleanExpiredSessions 清理所有过期 session
func cleanExpiredSessions() {
	sessionMux.Lock()
	now := time.Now()
	for token, data := range sessions {
		if now.After(data.expiry) {
			delete(sessions, token)
		}
	}
	sessionMux.Unlock()
}

// [L3] cleanExpiredLoginAttempts 清理过期的登录失败记录
// loginAttempts map 此前永不清理,长期运行会因大量不同 IP 累积导致内存泄漏;
// 删除锁定窗口已过(lockUntil + 一个 lockoutDuration 缓冲)的条目
func cleanExpiredLoginAttempts() {
	loginAttemptMux.Lock()
	now := time.Now()
	for ip, a := range loginAttempts {
		if now.After(a.lockUntil.Add(loginLockDuration)) {
			delete(loginAttempts, ip)
		}
	}
	loginAttemptMux.Unlock()
}

// requireAuth 鉴权中间件：未登录时页面 302 跳转 /login，API 返回 401 JSON
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil || !isValidSession(cookie.Value) {
			if r.URL.Path == "/api/logs" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "未登录"})
				return
			}
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// ===== [H6] 登录失败速率限制:同一 IP 失败 5 次锁定 15 分钟,防范暴力破解 =====
type loginAttempt struct {
	failures  int
	lockUntil time.Time
}

var (
	loginAttempts   = make(map[string]*loginAttempt)
	loginAttemptMux sync.Mutex
)

const (
	maxLoginFailures  = 5
	loginLockDuration = 15 * time.Minute
)

// isLoginLocked 返回 IP 是否处于登录锁定状态
func isLoginLocked(ip string) bool {
	loginAttemptMux.Lock()
	defer loginAttemptMux.Unlock()
	a, ok := loginAttempts[ip]
	if !ok {
		return false
	}
	return time.Now().Before(a.lockUntil)
}

// recordLoginFailure 记录一次登录失败,达到阈值后锁定
func recordLoginFailure(ip string) {
	loginAttemptMux.Lock()
	defer loginAttemptMux.Unlock()
	a, ok := loginAttempts[ip]
	if !ok {
		a = &loginAttempt{}
		loginAttempts[ip] = a
	}
	a.failures++
	if a.failures >= maxLoginFailures {
		a.lockUntil = time.Now().Add(loginLockDuration)
		a.failures = 0
	}
}

// clearLoginFailures 登录成功后清除该 IP 的失败记录
func clearLoginFailures(ip string) {
	loginAttemptMux.Lock()
	delete(loginAttempts, ip)
	loginAttemptMux.Unlock()
}

// [L2] trustProxy 控制是否信任 X-Forwarded-For/X-Real-IP 等代理头(默认 false)
// 仅当部署于可信反向代理之后时通过环境变量 TRUST_PROXY=true 开启;
// 默认不信任可防止客户端伪造 XFF 头绕过基于 IP 的登录速率限制
var trustProxy = false

// [L4][L2] clientIP 提取客户端 IP
// [L2] 仅当 trustProxy=true 时才读取代理头,否则直接使用 r.RemoteAddr 的 IP 部分
func clientIP(r *http.Request) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx > 0 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// [H5] requestIsHTTPS 判断请求是否经 HTTPS 传输(含反向代理场景)
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// [H5] setSessionCookie 统一设置会话 Cookie,含 HttpOnly/SameSite/Secure 安全属性
func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // 防范跨站 Cookie 发送
		Secure:   requestIsHTTPS(r),    // HTTPS 下自动启用 Secure
	})
}

// [M2] securityHeaders 为所有响应添加基础安全响应头
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "1; mode=block")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// ===== 全局会话级 Cookie 强制中间件 =====

// 预编译清洗正则（包级复用，避免每次请求重复编译）：
//   maxAgePositiveRe：匹配 Max-Age=<正整数>，不匹配 Max-Age=0，从而保留删除 Cookie 的语义
//   expiresRe：匹配 Expires=... 属性（属性值中不含分号）
var (
	maxAgePositiveRe = regexp.MustCompile(`Max-Age=[1-9]\d*`)
	expiresRe        = regexp.MustCompile(`Expires=[^;]*`)
)

// sessionCookieWriter 包装 http.ResponseWriter，在首次真正写出响应前清洗 Set-Cookie 响应头，
// 强制所有下发 Cookie 为会话级：剥离 Max-Age(>0) 与 Expires 属性，保留 Max-Age=0
// （删除 Cookie 的语义，登出时需要，不能破坏）。防范未来代码、中间件或插件意外设置持久化 Cookie。
type sessionCookieWriter struct {
	http.ResponseWriter
	once sync.Once // 保证整个响应周期内只清洗一次 Set-Cookie 头
}

// stripPersistentAttrs 清洗单个 cookie 字符串：
// 移除 Max-Age=<正整数>（保留 Max-Age=0 删除语义）与所有 Expires=... 属性，
// 清理移除属性后残留的空段与多余空格，保持 cookie 字符串格式整洁。
func stripPersistentAttrs(cookie string) string {
	// 先剥离 Expires 属性，再剥离正整数 Max-Age 属性（Max-Age=0 不受影响）
	s := expiresRe.ReplaceAllString(cookie, "")
	s = maxAgePositiveRe.ReplaceAllString(s, "")
	// 按分号分段，剔除移除属性后留下的空段，重新以 "; " 拼接，避免 "; ;" 残留
	parts := strings.Split(s, ";")
	kept := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			kept = append(kept, p)
		}
	}
	return strings.Join(kept, "; ")
}

// sanitizeOnce 在首次写出响应前完成 Set-Cookie 头清洗（sync.Once 保证仅执行一次）
func (w *sessionCookieWriter) sanitizeOnce() {
	w.once.Do(func() {
		cookies := w.Header()["Set-Cookie"]
		if len(cookies) == 0 {
			return
		}
		cleaned := make([]string, 0, len(cookies))
		for _, c := range cookies {
			if s := stripPersistentAttrs(c); s != "" {
				cleaned = append(cleaned, s)
			}
		}
		w.Header()["Set-Cookie"] = cleaned
	})
}

// WriteHeader 在写出状态码前清洗 Set-Cookie 头
func (w *sessionCookieWriter) WriteHeader(code int) {
	w.sanitizeOnce()
	w.ResponseWriter.WriteHeader(code)
}

// Write 在写出响应体前清洗 Set-Cookie 头（兜底：handler 未显式调用 WriteHeader 时由 Write 隐式触发）
func (w *sessionCookieWriter) Write(b []byte) (int, error) {
	w.sanitizeOnce()
	return w.ResponseWriter.Write(b)
}

// Flush 委托底层 writer 的 Flush（若支持），保证 SSE/流式场景下清洗时机不被绕过
func (w *sessionCookieWriter) Flush() {
	w.sanitizeOnce()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack 委托底层 writer 的 Hijack（若支持），兼容 websocket 场景
func (w *sessionCookieWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("底层 ResponseWriter 不支持 Hijack")
}

// enforceSessionCookies 全局中间件：包裹整个 http.Handler，
// 强制所有下发 Cookie 为会话级——剥离 Max-Age(>0)/Expires 属性，保留 Max-Age=0 删除语义。
// 在 main() 中包裹 http.DefaultServeMux，一处覆盖所有现有及未来路由。
func enforceSessionCookies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&sessionCookieWriter{ResponseWriter: w}, r)
	})
}

// [I4] 模板与正则仅解析/编译一次并缓存,避免每次请求重复解析磁盘文件
var (
	loginTmpl = template.Must(template.ParseFiles("templates/login.html"))
	indexTmpl = template.Must(template.ParseFiles("templates/index.html"))
	ipRegex   = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
)

// loginPageData 登录页模板数据
type loginPageData struct {
	Error string
	CSRF  string // [H3] 登录表单 CSRF token
}

// renderLogin 渲染登录页
func renderLogin(w http.ResponseWriter, data loginPageData) {
	// [I4] 使用启动时缓存的模板,不再每次请求解析
	if data.Error != "" {
		w.WriteHeader(http.StatusUnauthorized)
	}
	if err := loginTmpl.Execute(w, data); err != nil { // [L1] 检查模板执行错误
		log.Printf("登录页渲染失败: %v", err)
	}
}

// loginHandler 处理 GET/POST /login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// [L6] 已有有效会话直接重定向首页,不重复创建匿名会话,
		// 防止脚本反复 GET /login 撑满 MaxSessions 驱逐真实用户会话
		if cookie, err := r.Cookie("session_token"); err == nil && isValidSession(cookie.Value) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		// [H3] 无有效会话时才创建匿名会话预埋 CSRF token,供登录表单提交时校验
		token, csrf := createSession()
		setSessionCookie(w, r, token)
		renderLogin(w, loginPageData{CSRF: csrf})
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		// [H3] 校验 CSRF token
		if !validateCSRF(r) {
			token, csrf := createSession()
			setSessionCookie(w, r, token)
			renderLogin(w, loginPageData{Error: "会话已过期,请刷新重试", CSRF: csrf})
			return
		}
		// [H6] 登录速率限制:锁定期间拒绝尝试
		ip := clientIP(r)
		if isLoginLocked(ip) {
			log.Printf("[安全] 登录尝试被锁定, IP: %s", ip) // [L4] 不记录账号密码
			renderLogin(w, loginPageData{Error: "登录失败次数过多,请 15 分钟后再试"})
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		dataLock.Lock()
		authUser, authPass := config.AuthUser, config.AuthPass
		dataLock.Unlock()

		// [H2] 用户名恒定时间比较 + 密码哈希校验(兼容旧明文格式)
		if subtle.ConstantTimeCompare([]byte(username), []byte(authUser)) == 1 && verifyPassword(authPass, password) {
			// [I1] 旧单轮哈希自动升级为迭代拉伸哈希并持久化
			if isLegacySingleRoundHash(authPass, password) {
				dataLock.Lock()
				config.AuthPass = hashPassword(password)
				if err := saveConfigToFile(config); err != nil {
					log.Printf("[I1] 密码哈希升级保存失败: %v", err)
				}
				dataLock.Unlock()
			}
			// 登录成功:清除匿名会话与失败记录,创建正式会话
			if cookie, err := r.Cookie("session_token"); err == nil {
				deleteSession(cookie.Value)
			}
			clearLoginFailures(ip)
			token, _ := createSession()
			setSessionCookie(w, r, token) // [H5] 统一安全 Cookie 属性
			log.Printf("[安全] 登录成功, IP: %s", ip) // [L4] 不记录密码
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		recordLoginFailure(ip) // [H6]
		log.Printf("[安全] 登录失败, IP: %s", ip) // [L4] 不记录密码等 PII
		// [H3] 失败后重建匿名会话与 CSRF token
		token, csrf := createSession()
		setSessionCookie(w, r, token)
		renderLogin(w, loginPageData{Error: "账号或密码错误", CSRF: csrf})
		return
	}

	http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
}

// logoutHandler 处理 POST /logout：校验 CSRF 后删除 session、清除 cookie、跳转登录页
// [L2] 由 GET 改为 POST,防范登出 CSRF(恶意链接强制登出)
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) { // [H3]
		http.Error(w, "会话已过期", http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie("session_token"); err == nil {
		deleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,                 // [H5]
		SameSite: http.SameSiteLaxMode, // [H5]
		Secure:   requestIsHTTPS(r),    // [H5]
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// changePasswordHandler 处理 POST /api/change-password：修改登录账号密码
// 校验当前密码正确后，仅更新 AuthUser/AuthPass 并持久化，不影响其他配置
func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "方法不允许"})
		return
	}

	// [H3] 校验 CSRF token(前端通过 X-CSRF-Token 头提交)
	if !validateCSRF(r) {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "会话已过期,请刷新页面重试"})
		return
	}

	// [M6] 限制请求体大小为 1MB,防范超大请求 DoS
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewUser         string `json:"new_user"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "请求格式错误"})
		return
	}

	dataLock.Lock()
	// [H2] 使用恒定时间哈希校验当前密码,防止他人篡改
	if !verifyPassword(config.AuthPass, req.CurrentPassword) {
		dataLock.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "当前密码错误"})
		return
	}
	newUser := strings.TrimSpace(req.NewUser)
	newPass := strings.TrimSpace(req.NewPassword)
	if newUser == "" || newPass == "" {
		dataLock.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "新账号和新密码不能为空"})
		return
	}
	// 只更新鉴权字段，保留其他配置;[H2] 新密码以哈希存储
	config.AuthUser = newUser
	config.AuthPass = hashPassword(newPass)
	// [M4] 递增会话版本号并随配置持久化,使所有旧会话在下次校验时失效
	// (防范被窃取的会话 Cookie 在改密后仍然可用;版本号持久化确保重启后旧会话同样失效)
	config.SessionVersion++
	err := saveConfigToFile(config)
	dataLock.Unlock()

	if err != nil {
		log.Printf("修改账号密码失败: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "保存配置失败"})
		return
	}
	// [M4] 改密成功:删除当前旧会话 → 为当前请求创建新会话(保持用户登录) →
	// 其他所有旧会话因版本号不匹配在 isValidSession 中自动失效
	if cookie, cerr := r.Cookie("session_token"); cerr == nil {
		deleteSession(cookie.Value)
	}
	newToken, newCSRF := createSession()
	setSessionCookie(w, r, newToken) // [H5] 统一安全 Cookie 属性
	log.Printf("登录账号密码已修改（新账号: %s），所有旧会话已失效", newUser)
	// [M4] 返回新 CSRF token,前端需更新页面表单,否则后续请求会因 CSRF 不匹配失败
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "修改成功", "csrf": newCSRF})
}

// ===== 带耗时统计的 IP 查询函数 =====
func getPublicIP() (string, int64, string, error) {
	transport := &http.Transport{
		// [H4] 不再禁用 TLS 证书校验(InsecureSkipVerify),防范中间人攻击
		DialContext: (&net.Dialer{
			Timeout:   3 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		ResponseHeaderTimeout: 3 * time.Second,
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: transport,
	}

	endpoints := []string{
		"http://myip.ipip.net",
		"http://members.3322.org/dyndns/getip",
		"https://api.ipify.org",
		"https://api.ip.sb/ip",
	}

	var lastErr error
	// [I5] 变量名 url 遮蔽 net/url 包名,重命名为 endpoint
	for _, endpoint := range endpoints {
		start := time.Now()
		req, err := http.NewRequest("GET", endpoint, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "curl/7.88.1")

		resp, err := client.Do(req)
		elapsed := time.Since(start).Milliseconds()

		if err != nil {
			lastErr = err
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err == nil {
			matchedIP := ipRegex.FindString(string(body)) // [I4] 使用包级缓存正则
			if matchedIP != "" && net.ParseIP(matchedIP) != nil {
				return matchedIP, elapsed, endpoint, nil
			}
		}
	}

	return "", 0, "", fmt.Errorf("所有接口查询失败, 最后错误: %v", lastErr)
}

// ===== 纯 SSL 邮件发送（支持发件人名称与标题 RFC 2047 编码） =====

// [M7] sanitizeHeader 过滤邮件头值中的 CR/LF,防范 CRLF 邮件头注入
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(v)
}

func sendEmailSSL(smtpHost, smtpPort, user, pass, senderName, to, subject, content string) error {
	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
	host, _, _ := net.SplitHostPort(addr)

	msgID := fmt.Sprintf("<%d.%d@%s>", time.Now().UnixNano(), os.Getpid(), host)
	dateStr := time.Now().In(cstZone).Format(time.RFC1123Z)

	// 对邮件标题进行 RFC 2047 UTF-8 Base64 编码，解决中文和 Emoji 乱码问题
	encodedSubject := fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(subject)))

	// 拼装发件人信息([M7] 过滤 CRLF 注入)
	fromHeader := fmt.Sprintf("<%s>", sanitizeHeader(user))
	if senderName != "" {
		encodedSenderName := fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(sanitizeHeader(senderName))))
		fromHeader = fmt.Sprintf("%s <%s>", encodedSenderName, sanitizeHeader(user))
	}

	header := make(map[string]string)
	header["From"] = fromHeader
	header["To"] = fmt.Sprintf("<%s>", sanitizeHeader(to)) // [M7]
	header["Subject"] = encodedSubject
	header["Date"] = dateStr
	header["Message-ID"] = msgID
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = "text/plain; charset=UTF-8"

	message := ""
	for k, v := range header {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + content

	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host})
	if err != nil {
		return fmt.Errorf("TLS 连接失败: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer client.Quit()

	if err = client.Auth(smtp.PlainAuth("", user, pass, host)); err != nil {
		return fmt.Errorf("身份验证失败: %v", err)
	}
	if err = client.Mail(user); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(message))
	if err != nil {
		return err
	}
	return w.Close()
}

// ===== [M1] Webhook SSRF 防护 =====
// validateWebhookURL 校验 webhook URL 是否安全:仅允许 http/https;解析主机名,
// 若为域名则解析出 IP 后校验,禁止回环/私有/链路本地/未指定/多播地址,
// 防止服务端被诱导请求内网或云元数据地址(169.254.169.254)等敏感目标(SSRF)。
// 局限说明:域名场景存在 DNS rebinding TOCTOU 问题(校验时解析结果与实际请求时可能不同),
// 本实现仅校验解析结果,不做连接级 IP pin,该风险在本场景下可接受。
func validateWebhookURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("URL 解析失败: %v", err)
	}
	// url.Parse 已将 scheme 转为小写
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("仅支持 http/https 协议,当前为 %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL 缺少主机名")
	}
	if ip := net.ParseIP(host); ip != nil {
		// 主机部分为 IP 字面量,直接校验
		return validateWebhookIP(ip)
	}
	// 域名:解析后校验解析出的 IP(DNS rebinding TOCTOU 局限见函数注释)
	addr, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		return fmt.Errorf("域名 %s 解析失败: %v", host, err)
	}
	return validateWebhookIP(addr.IP)
}

// [L4] allowPrivateWebhook 控制是否允许 webhook 指向私网/回环地址(默认 false)
// 默认拦截以防范 SSRF;需推送内网群晖 Chat 等内网 webhook 时,
// 通过环境变量 ALLOW_PRIVATE_WEBHOOK=true 显式放行(协议限制与格式校验仍保留)
var allowPrivateWebhook = false

// [M1] validateWebhookIP 校验 IP 是否为禁止访问的敏感地址(均使用 net.IP 内置判定,无需手写 CIDR)
// [L4] allowPrivateWebhook=true 时跳过私网/回环等 IP 拦截
func validateWebhookIP(ip net.IP) error {
	if allowPrivateWebhook {
		return nil
	}
	switch {
	case ip.IsLoopback():
		return fmt.Errorf("禁止指向回环地址 %s", ip)
	case ip.IsPrivate():
		return fmt.Errorf("禁止指向私有内网地址 %s", ip)
	case ip.IsLinkLocalUnicast():
		return fmt.Errorf("禁止指向链路本地地址 %s(含云元数据 169.254.169.254)", ip)
	case ip.IsUnspecified():
		return fmt.Errorf("禁止指向未指定地址 %s", ip)
	case ip.IsMulticast():
		return fmt.Errorf("禁止指向多播地址 %s", ip)
	}
	return nil
}

func sendNotification(oldIP, currentIP string) {
	dataLock.Lock()
	cfg := config
	dataLock.Unlock()

	subject := "🌐 公网 IP 变动提醒"
	// 新 IP 放前面，旧 IP 放后面
	content := fmt.Sprintf(
		"您的公网 IP 已发生变更！\n\n"+
			"• 新 IP 地址：%s\n"+
			"• 旧 IP 地址：%s\n"+
			"• 变更时间：%s",
		currentIP, oldIP, time.Now().In(cstZone).Format("2006-01-02 15:04:05"),
	)

	if cfg.NotifyType == "email" && cfg.SMTPHost != "" {
		log.Printf("正在通过 SSL 发送邮件至 %s...", cfg.ToEmail)
		err := sendEmailSSL(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.SenderName, cfg.ToEmail, subject, content)
		if err != nil {
			log.Printf("邮件发送失败: %v", err)
		} else {
			log.Println("邮件发送成功")
		}
	} else if cfg.NotifyType == "webhook" && cfg.WebhookURL != "" {
		log.Println("正在发送 Webhook 推送...")

		var payload []byte
		targetURL := cfg.WebhookURL

		// 自动适配 WxPusher 格式
		if strings.Contains(targetURL, "wxpusher.zjiecode.com") {
			parts := strings.Split(targetURL, "/")
			var appToken, uid string
			for _, part := range parts {
				if strings.HasPrefix(part, "AT_") {
					appToken = part
				} else if strings.HasPrefix(part, "UID_") {
					uid = part
				}
			}

			wxData := map[string]interface{}{
				"appToken":    appToken,
				"content":     content,
				"summary":     subject,
				"contentType": 1,
				"uids":        []string{uid},
			}
			payload, _ = json.Marshal(wxData)
			targetURL = "https://wxpusher.zjiecode.com/api/send/message"
		} else if strings.Contains(targetURL, "SYNO.Chat.External") {
			// 群晖 Chat Webhook: payload 参数包含 JSON 字符串
			synoData := map[string]string{
				"text": content,
			}
			synoJSON, _ := json.Marshal(synoData)
			payload = []byte("payload=" + url.QueryEscape(string(synoJSON)))
		} else {
			payload, _ = json.Marshal(map[string]string{
				"title":   subject,
				"content": content,
				"text":    content,
			})
		}

		contentType := "application/json"
		if strings.Contains(targetURL, "SYNO.Chat.External") {
			contentType = "application/x-www-form-urlencoded"
		}
		// [M1] SSRF 防护:发送前校验最终请求地址(含 WxPusher 重写后的地址),
		// 校验失败则中止发送;这是保存时校验之外的二次防线(防 DNS 变更/绕过保存校验)
		if err := validateWebhookURL(targetURL); err != nil {
			log.Printf("[M1] Webhook 推送已中止(URL 校验失败): %v", err)
			return
		}
		webhookClient := &http.Client{
			Timeout: 10 * time.Second,
			// [L1] 自定义 CheckRedirect:默认 http.Client 跟随 302 重定向,
			// 攻击者可将公网 webhook 重定向到内网地址(如 169.254.169.254)绕过 SSRF 校验;
			// 每次重定向前对 Location URL 重新执行 validateWebhookURL,失败则返回错误阻止跳转
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if err := validateWebhookURL(req.URL.String()); err != nil {
					return fmt.Errorf("[L1] 重定向目标未通过 SSRF 校验: %w", err)
				}
				return nil
			},
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 5 * time.Second,
				}).DialContext,
				// [H4] 不再禁用 TLS 证书校验,防范中间人攻击
				ResponseHeaderTimeout: 5 * time.Second,
			},
		}
		resp, err := webhookClient.Post(targetURL, contentType, bytes.NewBuffer(payload))
		if err != nil {
			log.Printf("Webhook 推送失败: %v", err)
		} else {
			resp.Body.Close()
			// [M10] 仅记录状态码,不记录响应体(响应体可能含敏感 token 信息)
			log.Printf("Webhook 响应状态码: %d", resp.StatusCode)
		}
	}
}

// ===== 后台 IP 检测任务 =====
func ipCheckerWorker() {
	for {
		dataLock.Lock()
		interval := config.IntervalMinutes
		dataLock.Unlock()
		if interval < 1 {
			interval = 5
		}

		ip, ms, source, err := getPublicIP()
		nowStr := time.Now().In(cstZone).Format("15:04:05")

		if err == nil && ip != "" {
			dataLock.Lock()
			oldIP := status.LastIP
			status.LastIP = ip
			status.QueryTime = ms
			status.LastCheck = nowStr
			status.UsedSource = source
			dataLock.Unlock()

			if oldIP != "" && ip != oldIP {
				log.Printf("检测到公网 IP 变动: %s -> %s (耗时: %dms, 来自: %s)", oldIP, ip, ms, source)
				sendNotification(oldIP, ip)
			} else {
				log.Printf("检查完成，IP 未变动 (%s | 耗时: %dms)", ip, ms)
			}
		} else {
			log.Printf("获取公网 IP 失败: %v", err)
		}

		time.Sleep(time.Duration(interval) * time.Minute)
	}
}

func main() {
	log.SetOutput(logBuf)
	log.SetFlags(0)

	// [L2] TRUST_PROXY=true 时才信任 X-Forwarded-For 等代理头(默认 false,防伪造 XFF 绕过速率限制)
	trustProxy = strings.EqualFold(os.Getenv("TRUST_PROXY"), "true")
	// [L4] ALLOW_PRIVATE_WEBHOOK=true 时允许 webhook 指向私网/回环地址(默认 false,防 SSRF)
	allowPrivateWebhook = strings.EqualFold(os.Getenv("ALLOW_PRIVATE_WEBHOOK"), "true")

	loadConfig()
	log.Println("服务初始化完成，开始后台监控...")
	go ipCheckerWorker()

	http.HandleFunc("/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// [H3] 校验 CSRF token,防范跨站请求伪造
			if !validateCSRF(r) {
				http.Error(w, "会话已过期,请刷新页面重试", http.StatusForbidden)
				return
			}
			r.ParseForm()
			var newCfg Config
			newCfg.NotifyType = r.FormValue("notify_type")
			newCfg.SMTPHost = r.FormValue("smtp_host")
			newCfg.SMTPPort = r.FormValue("smtp_port")
			newCfg.SMTPUser = r.FormValue("smtp_user")
			newCfg.SMTPPass = r.FormValue("smtp_pass")
			newCfg.SenderName = r.FormValue("sender_name") // 获取表单中的发件人名称
			newCfg.ToEmail = r.FormValue("to_email")
			newCfg.WebhookURL = r.FormValue("webhook_url")
			fmt.Sscanf(r.FormValue("interval_minutes"), "%d", &newCfg.IntervalMinutes)
			// [L9] 校验检查间隔下限:为 0 会导致后台任务死循环式频繁检查,非法值拒绝保存
			if newCfg.IntervalMinutes < 1 {
				http.Error(w, "检查间隔(分钟)不能小于 1", http.StatusBadRequest)
				return
			}

			// 保留登录鉴权配置：表单提交了新值则更新，否则沿用当前值，避免保存配置时被清空
			dataLock.Lock()
			curAuthUser, curAuthPass := config.AuthUser, config.AuthPass
			curLoginExpire := config.LoginExpireHours
			curSMTPPass := config.SMTPPass // [M3] 密码不回显前端,提交为空时沿用旧值
			curSessionVersion := config.SessionVersion // [M4] 保留会话版本号,避免保存配置时被重置导致旧会话意外存活
			dataLock.Unlock()
			if newCfg.SMTPPass == "" {
				newCfg.SMTPPass = curSMTPPass // [M3] 前端不再回显密码,留空表示不修改
			}
			if newCfg.AuthUser = r.FormValue("auth_user"); newCfg.AuthUser == "" {
				newCfg.AuthUser = curAuthUser
			}
			if newCfg.AuthPass = r.FormValue("auth_pass"); newCfg.AuthPass == "" {
				newCfg.AuthPass = curAuthPass
			}
			// 登录有效期：表单提交了合法值(>0)则更新，解析失败或未提交时沿用当前值
			var formExpire int
			fmt.Sscanf(r.FormValue("login_expire_hours"), "%d", &formExpire)
			if formExpire > 0 {
				newCfg.LoginExpireHours = formExpire
			} else {
				newCfg.LoginExpireHours = curLoginExpire
			}

			newCfg.SessionVersion = curSessionVersion // [M4] 沿用当前会话版本号
			// [M1] SSRF 防护:保存前校验 webhook URL,禁止指向内网/回环/链路本地等敏感地址;
			// 校验失败返回明确错误信息给前端,不保存该配置
			if newCfg.WebhookURL != "" {
				if verr := validateWebhookURL(newCfg.WebhookURL); verr != nil {
					log.Printf("[M1] Webhook URL 校验失败: %v", verr)
					http.Error(w, "Webhook URL 校验失败: "+verr.Error(), http.StatusBadRequest)
					return
				}
			}

			if err := saveConfig(newCfg); err != nil {
				// [L5] 保存失败不再静默吞掉:记录日志并向前端返回错误响应
				log.Printf("[L5] 配置保存失败: %v", err)
				http.Error(w, "配置保存失败: "+err.Error(), http.StatusInternalServerError)
				return
			}
			log.Println("配置已更新并保存")
			if r.FormValue("action") == "test" {
				dataLock.Lock()
				curIP := status.LastIP
				dataLock.Unlock()

				// 取消模拟 IP，若不存在旧 IP 则设为未收录
				oldIP := "未收录"
				if curIP != "" {
					oldIP = curIP
				}

				go sendNotification(oldIP, curIP+" (测试推送)")
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// [I4] 使用启动时缓存的模板,不再每次请求解析
		dataLock.Lock()
		cfgSnapshot := config
		cfgSnapshot.SMTPPass = "" // [M3] 不向前端回显 SMTP 密码
		data := struct {
			Config Config
			Status Status
			CSRF   string // [H3] 表单 CSRF token
		}{Config: cfgSnapshot, Status: status}
		dataLock.Unlock()
		if cookie, err := r.Cookie("session_token"); err == nil {
			data.CSRF = getCSRFToken(cookie.Value) // [H3]
		}
		if err := indexTmpl.Execute(w, data); err != nil { // [L1] 检查模板执行错误
			log.Printf("模板渲染失败: %v", err)
		}
	}))

	http.HandleFunc("/api/logs", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logBuf.GetLogs())
	}))

	http.HandleFunc("/api/change-password", requireAuth(changePasswordHandler))

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	// 定期清理过期 session 与过期登录失败记录([L3] 防止 loginAttempts 内存泄漏)
	go func() {
		ticker := time.NewTicker(time.Hour)
		for range ticker.C {
			cleanExpiredSessions()
			cleanExpiredLoginAttempts()
		}
	}()

	log.Println("Web 界面已启动，请通过浏览器访问 49809 端口")
	// [M2] 安全响应头 + 全局强制会话级 Cookie：包裹 DefaultServeMux，一处覆盖所有现有及未来路由
	handler := securityHeaders(enforceSessionCookies(http.DefaultServeMux))
	// [M5] 设置读写超时,防范慢速连接 DoS
	server := &http.Server{
		Addr:              ":49809",
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}