package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kardianos/service"
	"golang.org/x/crypto/ssh"
)

// --- 配置结构体更新 ---
type Config struct {
	Bemfa struct {
		Host  string `json:"host"`
		UID   string `json:"uid"`
		Topic string `json:"topic"`
	} `json:"bemfa"`
	WOL struct {
		MAC         string `json:"mac"`
		BroadcastIP string `json:"broadcast_ip"`
	} `json:"wol"`
	SSH struct {
		IP             string `json:"ip"`
		User           string `json:"user"`
		PrivateKeyPath string `json:"private_key_path"` // 替换了 Password
		ShutdownCmd    string `json:"shutdown_cmd"`
	} `json:"ssh"`
}

var (
	cfg        Config
	logger     service.Logger
	configName = "config.json"
)

// Service 结构体 (保持不变)
type program struct{}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}
func (p *program) Stop(s service.Service) error { return nil }

func main() {
	// ... (Service 初始化代码与之前相同，为节省篇幅省略，请保留之前的 Service 初始化部分) ...
    // 下面直接展示核心逻辑的变化
    
	svcConfig := &service.Config{
		Name:        "wol",
		DisplayName: "WOL Service",
		Description: "Bemfa Remote Control",
	}
	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil { log.Fatal(err) }
	logger, _ = s.Logger(nil)

	if len(os.Args) > 1 {
		if os.Args[1] == "install" {
			s.Install(); fmt.Println("Installed"); return
		} else if os.Args[1] == "uninstall" {
			s.Stop(); s.Uninstall(); fmt.Println("Uninstalled"); return
		}
	}
	s.Run()
}

func (p *program) run() {
	// 获取程序运行目录
	exePath, _ := os.Executable()
	configDir := filepath.Dir(exePath)
	configPath := filepath.Join(configDir, configName)

	if err := loadConfig(configPath); err != nil {
		logger.Errorf("无法加载配置: %v", err)
		return
	}
	logger.Infof("服务启动，使用SSH Key: %s", cfg.SSH.PrivateKeyPath)

	for {
		connectBemfa()
		logger.Warning("连接断开，10秒后重试...")
		time.Sleep(10 * time.Second)
	}
}

func loadConfig(path string) error {
	file, err := os.Open(path)
	if err != nil { return err }
	defer file.Close()
	return json.NewDecoder(file).Decode(&cfg)
}

func connectBemfa() {
	conn, err := net.Dial("tcp", cfg.Bemfa.Host)
	if err != nil {
		logger.Errorf("连接巴法云失败: %v", err)
		return
	}
	defer conn.Close()

	// 发送订阅
	authCmd := fmt.Sprintf("cmd=1&uid=%s&topic=%s\r\n", cfg.Bemfa.UID, cfg.Bemfa.Topic)
	conn.Write([]byte(authCmd))

	// 改进：使用 Context 或 Channel 来控制 Ping 协程的退出
	// 简单做法：Ping 失败直接退出，不依赖外部关闭
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			// 设置写入超时，防止卡死
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("ping\r\n")); err != nil {
				// 写入失败意味着连接已断开，退出协程
				return
			}
		}
	}()

	logger.Info("已连接巴法云")
	reader := bufio.NewReader(conn)
	
	for {
		// 改进：设置读取超时 (巴法云心跳通常是60s，设置70s超时)
		// 如果70秒没收到任何数据（哪怕是心跳回复），认为连接假死
		conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		
		msg, err := reader.ReadString('\n')
		if err != nil {
			logger.Errorf("连接读取错误 (可能是超时或断开): %v", err)
			return
		}
		handleMessage(msg)
	}
}

func handleMessage(msg string) {
	msg = strings.TrimSpace(msg)
	if strings.Contains(msg, "on") {
		logger.Info("执行：WOL 唤醒")
		wakeOnLan(cfg.WOL.MAC, cfg.WOL.BroadcastIP)
	} else if strings.Contains(msg, "off") {
		logger.Info("执行：SSH 关机")
		sshShutdown()
	}
}

// WOL 函数保持不变...
func wakeOnLan(macAddr, broadcastIP string) {
    // ... (请复制之前的 WOL 代码) ...
    // 为节省篇幅省略
    mac, _ := net.ParseMAC(macAddr)
    packet := []byte{}
    for i := 0; i < 6; i++ { packet = append(packet, 0xFF) }
    for i := 0; i < 16; i++ { packet = append(packet, mac...) }
    localAddr, _ := net.ResolveUDPAddr("udp", ":0")
    remoteAddr, _ := net.ResolveUDPAddr("udp", broadcastIP)
    conn, _ := net.DialUDP("udp", localAddr, remoteAddr)
    defer conn.Close()
    conn.Write(packet)
}

// 重点修改：SSH 免密登录逻辑
func sshShutdown() {
	// 1. 读取私钥文件
	key, err := os.ReadFile(cfg.SSH.PrivateKeyPath)
	if err != nil {
		logger.Errorf("无法读取私钥文件: %v", err)
		return
	}

	// 2. 解析私钥
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		logger.Errorf("私钥解析失败 (是否有密码保护?): %v", err)
		return
	}

	// 3. 配置使用 PublicKeys 认证
	config := &ssh.ClientConfig{
		User: cfg.SSH.User,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 内网信任
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", cfg.SSH.IP, config)
	if err != nil {
		logger.Errorf("SSH 连接失败: %v", err)
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		logger.Errorf("SSH Session 创建失败: %v", err)
		return
	}
	defer session.Close()

	logger.Infof("发送关机命令: %s", cfg.SSH.ShutdownCmd)
	
	// 4. 执行命令并优雅处理“断开”错误
	if err := session.Run(cfg.SSH.ShutdownCmd); err != nil {
		// 如果错误是 "wait: remote command exited without exit status or exit signal"
		// 或者包含 "255" 等，通常是因为网络被切断了，这对关机来说是正常的
		if strings.Contains(err.Error(), "255") || strings.Contains(err.Error(), "exited without") {
			logger.Info("关机命令已发送 (连接已按预期断开)")
		} else {
			logger.Errorf("执行关机命令返回错误: %v", err)
		}
	} else {
		logger.Info("关机命令执行成功")
	}
}