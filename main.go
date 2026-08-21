package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
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
		config = Config{IntervalMinutes: 10, NotifyType: "webhook"}
	}
}

func saveConfig(newCfg Config) error {
	dataLock.Lock()
	defer dataLock.Unlock()
	config = newCfg
	data, _ := json.MarshalIndent(config, "", "  ")
	os.MkdirAll("/data", 0755)
	return os.WriteFile(configFile, data, 0644)
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
		} else {
			payload, _ = json.Marshal(map[string]string{
				"title":   subject,
				"content": content,
				"text":    content,
			})
		}

		resp, err := http.Post(targetURL, "application/json", bytes.NewBuffer(payload))
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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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
	})

	http.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logBuf.GetLogs())
	})

	log.Println("Web 界面运行在 :49809")
	log.Fatal(http.ListenAndServe(":49809", nil))
}