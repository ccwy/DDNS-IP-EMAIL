package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

// ===== 日志内存缓冲区实现 =====
type LogMemory struct {
	mu   sync.Mutex
	logs []string
	max  int
}

func NewLogMemory(maxLines int) *LogMemory {
	return &LogMemory{
		logs: make([]string, 0, maxLines),
		max:  maxLines,
	}
}

func (l *LogMemory) Write(p []byte) (n int, err int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	line := strings.TrimSpace(string(p))
	if line != "" {
		if len(l.logs) >= l.max {
			l.logs = l.logs[1:] // 超过最大行数移除最旧的一条
		}
		l.logs = append(l.logs, fmt.Sprintf("[%s] %s", time.Now().Format("15:04:05"), line))
	}
	return os.Stdout.Write(p) // 同时输出到终端控制台
}

func (l *LogMemory) GetLogs() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := make([]string, len(l.logs))
	copy(result, l.logs)
	return result
}

var logBuf = NewLogMemory(100) // 内存中最多保留 100 条最新日志

// ===== 核心数据定义 =====
type Config struct {
	IntervalMinutes int    `json:"interval_minutes"`
	NotifyType      string `json:"notify_type"`
	SMTPHost        string `json:"smtp_host"`
	SMTPPort        string `json:"smtp_port"`
	SMTPUser        string `json:"smtp_user"`
	SMTPPass        string `json:"smtp_pass"`
	ToEmail         string `json:"to_email"`
	WebhookURL      string `json:"webhook_url"`
}

var (
	config     Config
	configLock sync.Mutex
	lastIP     string
	configFile = "/data/config.json"
)

func loadConfig() {
	configLock.Lock()
	defer configLock.Unlock()
	file, err := os.ReadFile(configFile)
	if err == nil {
		json.Unmarshal(file, &config)
	} else {
		config = Config{IntervalMinutes: 10, NotifyType: "webhook"}
	}
}

func saveConfig(newCfg Config) error {
	configLock.Lock()
	defer configLock.Unlock()
	config = newCfg
	data, _ := json.MarshalIndent(config, "", "  ")
	os.MkdirAll("/data", 0755)
	return os.WriteFile(configFile, data, 0644)
}

func sendEmailSSL(smtpHost, smtpPort, user, pass, to, subject, content string) error {
	addr := fmt.Sprintf("%s:%s", smtpHost, smtpPort)
	host, _, _ := net.SplitHostPort(addr)

	header := make(map[string]string)
	header["From"] = user
	header["To"] = to
	header["Subject"] = subject
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
	w.Write([]byte(message))
	return w.Close()
}

func sendNotification(currentIP string) {
	configLock.Lock()
	cfg := config
	configLock.Unlock()

	subject := "公网 IP 变动提醒"
	content := fmt.Sprintf("您的最新公网 IP 为：%s\n更新时间：%s", currentIP, time.Now().Format("2006-01-02 15:04:05"))

	if cfg.NotifyType == "email" && cfg.SMTPHost != "" {
		log.Printf("正在通过 SSL 发送邮件至 %s...", cfg.ToEmail)
		err := sendEmailSSL(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUser, cfg.SMTPPass, cfg.ToEmail, subject, content)
		if err != nil {
			log.Printf("邮件发送失败: %v", err)
		} else {
			log.Println("邮件发送成功")
		}
	} else if cfg.NotifyType == "webhook" && cfg.WebhookURL != "" {
		log.Println("正在发送 Webhook 推送...")
		payload, _ := json.Marshal(map[string]string{"title": subject, "content": content, "text": content})
		resp, err := http.Post(cfg.WebhookURL, "application/json", bytes.NewBuffer(payload))
		if err != nil {
			log.Printf("Webhook 推送失败: %v", err)
		} else {
			resp.Body.Close()
			log.Println("Webhook 推送成功")
		}
	}
}

func getPublicIP() (string, error) {
	resp, err := http.Get("https://api.ipify.org")
	if err != nil {
		resp, err = http.Get("https://ddns.oray.com/checkip")
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(bytes.TrimSpace(body)), nil
}

func ipCheckerWorker() {
	for {
		configLock.Lock()
		interval := config.IntervalMinutes
		configLock.Unlock()
		if interval < 1 {
			interval = 5
		}

		ip, err := getPublicIP()
		if err == nil && ip != "" {
			if lastIP != "" && ip != lastIP {
				log.Printf("IP 发生变动: %s -> %s", lastIP, ip)
				sendNotification(ip)
			} else {
				log.Printf("检查完成，IP 未变动 (%s)", ip)
			}
			lastIP = ip
		} else {
			log.Printf("获取公网 IP 失败: %v", err)
		}

		time.Sleep(time.Duration(interval) * time.Minute)
	}
}

func main() {
	// 将 log 输出重定向至自定义的 LogMemory
	log.SetOutput(logBuf)
	log.SetFlags(0)

	loadConfig()
	log.Println("服务初始化完成，开始后台监控...")
	go ipCheckerWorker()

	// 主页面
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.ParseForm()
			var newCfg Config
			newCfg.NotifyType = r.FormValue("notify_type")
			newCfg.SMTPHost = r.FormValue("smtp_host")
			newCfg.SMTPPort = r.FormValue("smtp_port")
			newCfg.SMTPUser = r.FormValue("smtp_user")
			newCfg.SMTPPass = r.FormValue("smtp_pass")
			newCfg.ToEmail = r.FormValue("to_email")
			newCfg.WebhookURL = r.FormValue("webhook_url")
			fmt.Sscanf(r.FormValue("interval_minutes"), "%d", &newCfg.IntervalMinutes)

			if err := saveConfig(newCfg); err == nil {
				log.Println("配置已成功更新并保存")
				if r.FormValue("action") == "test" && lastIP != "" {
					go sendNotification(lastIP + " (测试推送)")
				}
			}
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		tmpl, _ := template.ParseFiles("templates/index.html")
		configLock.Lock()
		data := struct {
			Config Config
			LastIP string
		}{Config: config, LastIP: lastIP}
		configLock.Unlock()
		tmpl.Execute(w, data)
	})

	// 获取实时日志接口 (JSON)
	http.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logBuf.GetLogs())
	})

	log.Println("Web 界面运行在 :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}