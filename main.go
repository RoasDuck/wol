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
		PrivateKeyPath string `json:"private_key_path"`
		ShutdownCmd    string `json:"shutdown_cmd"`
	} `json:"ssh"`
}

var (
	cfg        Config
	logger     service.Logger
	configName = "config.json"
)

type program struct{}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}
func (p *program) Stop(s service.Service) error { return nil }

func main() {
	svcConfig := &service.Config{
		Name:        "wol",
		DisplayName: "WOL Service",
		Description: "Bemfa Remote Control Service",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}

	logger, err = s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}

	// 简单的命令行控制
	if len(os.Args) > 1 {
		cmd := os.Args[1]
		if cmd == "install" {
			if err := s.Install(); err != nil {
				log.Fatalf("安装失败: %v", err)
			}
			fmt.Println("服务安装成功！")
			if err := s.Start(); err != nil {
				log.Fatalf("启动失败: %v", err)
			}
			fmt.Println("服务已启动！")
			return
		} else if cmd == "uninstall" {
			s.Stop() // 尝试停止，忽略错误
			if err := s.Uninstall(); err != nil {
				log.Fatalf("卸载失败: %v", err)
			}
			fmt.Println("服务已卸载！")
			return
		}
	}

	if err = s.Run(); err != nil {
		logger.Error(err)
	}
}

func (p *program) run() {
	exePath, err := os.Executable()
	if err != nil {
		logger.Errorf("无法获取路径: %v", err)
		return
	}
	configPath := filepath.Join(filepath.Dir(exePath), configName)

	if err := loadConfig(configPath); err != nil {
		logger.Errorf("加载配置失败 [%s]: %v", configPath, err)
		return
	}
	logger.Infof("服务启动，监听主题: %s", cfg.Bemfa.Topic)

	for {
		connectBemfa()
		logger.Warning("连接断开，10秒后重试...")
		time.Sleep(10 * time.Second)
	}
}

func loadConfig(path string) error {
	data, err := os.ReadFile(path) // 使用现代的 os.ReadFile
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &cfg)
}

func connectBemfa() {
	conn, err := net.Dial("tcp", cfg.Bemfa.Host)
	if err != nil {
		logger.Errorf("连接巴法云失败: %v", err)
		return
	}
	defer conn.Close()

	authCmd := fmt.Sprintf("cmd=1&uid=%s&topic=%s\r\n", cfg.Bemfa.UID, cfg.Bemfa.Topic)
	if _, err := conn.Write([]byte(authCmd)); err != nil {
		return
	}

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := conn.Write([]byte("ping\r\n")); err != nil {
				return
			}
		}
	}()

	logger.Info("已连接巴法云")
	reader := bufio.NewReader(conn)
	for {
		// 70秒无响应判定为断连
		conn.SetReadDeadline(time.Now().Add(70 * time.Second))
		msg, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		handleMessage(msg)
	}
}

func handleMessage(msg string) {
	msg = strings.TrimSpace(msg)
	if strings.Contains(msg, "on") {
		logger.Info("收到指令: 开机 (WOL)")
		wakeOnLan(cfg.WOL.MAC, cfg.WOL.BroadcastIP)
	} else if strings.Contains(msg, "off") {
		logger.Info("收到指令: 关机 (SSH)")
		sshShutdown()
	}
}

func wakeOnLan(macAddr, broadcastIP string) {
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		logger.Errorf("MAC地址错误: %v", err)
		return
	}
	// 构建 Magic Packet
	packet := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		packet = append(packet, 0xFF)
	}
	for i := 0; i < 16; i++ {
		packet = append(packet, mac...)
	}

	localAddr, _ := net.ResolveUDPAddr("udp", ":0")
	remoteAddr, err := net.ResolveUDPAddr("udp", broadcastIP)
	if err != nil {
		logger.Errorf("广播地址错误: %v", err)
		return
	}

	conn, err := net.DialUDP("udp", localAddr, remoteAddr)
	if err != nil {
		logger.Errorf("UDP错误: %v", err)
		return
	}
	defer conn.Close()

	conn.Write(packet)
	logger.Infof("已向 %s 发送唤醒包", broadcastIP)
}

func sshShutdown() {
	key, err := os.ReadFile(cfg.SSH.PrivateKeyPath)
	if err != nil {
		logger.Errorf("读取私钥失败: %v", err)
		return
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		logger.Errorf("解析私钥失败: %v", err)
		return
	}

	config := &ssh.ClientConfig{
		User:            cfg.SSH.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 局域网内忽略HostKey检查
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", cfg.SSH.IP, config)
	if err != nil {
		logger.Errorf("SSH连接失败: %v", err)
		return
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		logger.Errorf("Session失败: %v", err)
		return
	}
	defer session.Close()

	logger.Infof("发送关机命令: %s", cfg.SSH.ShutdownCmd)
	if err := session.Run(cfg.SSH.ShutdownCmd); err != nil {
		// 忽略网络断开引起的错误
		if strings.Contains(err.Error(), "255") || strings.Contains(err.Error(), "exited without") {
			logger.Info("命令已发送 (连接断开)")
		} else {
			logger.Errorf("执行错误: %v", err)
		}
	}
}
