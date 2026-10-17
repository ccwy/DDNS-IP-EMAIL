package main

import (
	"bytes"
	"crypto/rand"
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
		json.Unmarshal(file, &config)
	} else {
		config = Config{IntervalMinutes: 2, NotifyType: "email"}
	}
	// 鉴权字段为空时设置默认值并立即持久化
	changed := false
	if config.AuthUser == "" {
		config.AuthUser = "admin"
		changed = true
	}
	if config.AuthPass == "" {
		config.AuthPass = "admin"
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
func saveConfigToFile(cfg Config) error {
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.MkdirAll("/data", 0755)
	return os.WriteFile(configFile, data, 0644)
}

func saveConfig(newCfg Config) error {
	dataLock.Lock()
	defer dataLock.Unlock()
	config = newCfg
	return saveConfigToFile(config)
}

// ===== Session 管理与登录鉴权 =====
var (
	sessions   = make(map[string]time.Time) // token -> 过期时间
	sessionMux sync.Mutex
)

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

// createSession 生成 32 字节随机 hex token
// Cookie 为会话级（不设 MaxAge，关闭浏览器即登出）；未关闭窗口时由服务端 session 按配置有效期自动过期（滑动续期）
func createSession() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// 极少发生，使用时间戳兜底
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	token := hex.EncodeToString(b)
	sessionMux.Lock()
	sessions[token] = time.Now().Add(getSessionTimeout())
	sessionMux.Unlock()
	return token
}

// isValidSession 校验 session 是否存在且未过期，过期则删除；校验通过时滑动续期
func isValidSession(token string) bool {
	if token == "" {
		return false
	}
	sessionMux.Lock()
	defer sessionMux.Unlock()
	expiry, ok := sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(sessions, token)
		return false
	}
	// 滑动续期：校验通过即刷新闲置过期时间，浏览器保持打开期间不会过期
	sessions[token] = time.Now().Add(getSessionTimeout())
	return true
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
	for token, expiry := range sessions {
		if now.After(expiry) {
			delete(sessions, token)
		}
	}
	sessionMux.Unlock()
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

// loginPageData 登录页模板数据
type loginPageData struct {
	Error     string
	IsDefault bool
}

// renderLogin 渲染登录页
func renderLogin(w http.ResponseWriter, data loginPageData) {
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, "登录页加载失败", http.StatusInternalServerError)
		return
	}
	if data.Error != "" {
		w.WriteHeader(http.StatusUnauthorized)
	}
	tmpl.Execute(w, data)
}

// loginHandler 处理 GET/POST /login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// 已登录则直接进入面板
		if cookie, err := r.Cookie("session_token"); err == nil && isValidSession(cookie.Value) {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		dataLock.Lock()
		isDefault := config.AuthUser == "admin" && config.AuthPass == "admin"
		dataLock.Unlock()
		renderLogin(w, loginPageData{IsDefault: isDefault})
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		dataLock.Lock()
		authUser, authPass := config.AuthUser, config.AuthPass
		dataLock.Unlock()

		if username == authUser && password == authPass {
			token := createSession()
			// 会话级 Cookie：不设 MaxAge，关闭浏览器即登出；未关闭时由服务端 session 按配置有效期自动过期
			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    token,
				Path:     "/",
				HttpOnly: true,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		renderLogin(w, loginPageData{
			Error:     "账号或密码错误",
			IsDefault: authUser == "admin" && authPass == "admin",
		})
		return
	}

	http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
}

// logoutHandler 处理 GET /logout：删除 session、清除 cookie、跳转登录页
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("session_token"); err == nil {
		deleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "session_token",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
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
	// 校验当前密码，防止他人篡改
	if config.AuthPass != req.CurrentPassword {
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
	// 只更新鉴权字段，保留其他配置
	config.AuthUser = newUser
	config.AuthPass = newPass
	err := saveConfigToFile(config)
	dataLock.Unlock()

	if err != nil {
		log.Printf("修改账号密码失败: %v", err)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "保存配置失败"})
		return
	}
	log.Printf("登录账号密码已修改（新账号: %s）", newUser)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "message": "修改成功，请重新登录"})
}

// ===== 带耗时统计的 IP 查询函数 =====
func getPublicIP() (string, int64, string, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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

	ipRegex := regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
	endpoints := []string{
		"http://myip.ipip.net",
		"http://members.3322.org/dyndns/getip",
		"https://api.ipify.org",
		"https://api.ip.sb/ip",
	}

	var lastErr error
	for _, url := range endpoints {
		start := time.Now()
		req, err := http.NewRequest("GET", url, nil)
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
			matchedIP := ipRegex.FindString(string(body))
			if matchedIP != "" && net.ParseIP(matchedIP) != nil {
				return matchedIP, elapsed, url, nil
			}
		}
	}

	return "", 0, "", fmt.Errorf("所有接口查询失败, 最后错误: %v", lastErr)
}

// ===== 纯 SSL 邮件发送（支持发件人名称与标题 RFC 2047 编码） =====
func sendEmailSSL(smtpHost, smtpPort, user, pass, senderName, to, subject, content string) error {
	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
	host, _, _ := net.SplitHostPort(addr)

	msgID := fmt.Sprintf("<%d.%d@%s>", time.Now().UnixNano(), os.Getpid(), host)
	dateStr := time.Now().In(cstZone).Format(time.RFC1123Z)

	// 对邮件标题进行 RFC 2047 UTF-8 Base64 编码，解决中文和 Emoji 乱码问题
	encodedSubject := fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(subject)))

	// 拼装发件人信息
	fromHeader := fmt.Sprintf("<%s>", user)
	if senderName != "" {
		encodedSenderName := fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(senderName)))
		fromHeader = fmt.Sprintf("%s <%s>", encodedSenderName, user)
	}

	header := make(map[string]string)
	header["From"] = fromHeader
	header["To"] = fmt.Sprintf("<%s>", to)
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
		webhookClient := &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: 5 * time.Second,
				}).DialContext,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				ResponseHeaderTimeout: 5 * time.Second,
			},
		}
		resp, err := webhookClient.Post(targetURL, contentType, bytes.NewBuffer(payload))
		if err != nil {
			log.Printf("Webhook 推送失败: %v", err)
		} else {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("Webhook 响应: %s", string(body))
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

	loadConfig()
	log.Println("服务初始化完成，开始后台监控...")
	go ipCheckerWorker()

	http.HandleFunc("/", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
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

			// 保留登录鉴权配置：表单提交了新值则更新，否则沿用当前值，避免保存配置时被清空
			dataLock.Lock()
			curAuthUser, curAuthPass := config.AuthUser, config.AuthPass
			curLoginExpire := config.LoginExpireHours
			dataLock.Unlock()
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

			if err := saveConfig(newCfg); err == nil {
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
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		tmpl, _ := template.ParseFiles("templates/index.html")
		dataLock.Lock()
		data := struct {
			Config Config
			Status Status
		}{Config: config, Status: status}
		dataLock.Unlock()
		tmpl.Execute(w, data)
	}))

	http.HandleFunc("/api/logs", requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logBuf.GetLogs())
	}))

	http.HandleFunc("/api/change-password", requireAuth(changePasswordHandler))

	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)

	// 定期清理过期 session
	go func() {
		ticker := time.NewTicker(time.Hour)
		for range ticker.C {
			cleanExpiredSessions()
		}
	}()

	log.Println("Web 界面运行在 :49809")
	log.Fatal(http.ListenAndServe(":49809", nil))
}