package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config 配置结构体
type Config struct {
	Addr   string `json:"addr"`
	Secret string `json:"secret"`
	Http   int    `json:"http"`
	Tls    int    `json:"tls"`
	Socks  int    `json:"socks"`
}

// LoadConfig 加载配置文件
func LoadConfig(configPath string) (*Config, error) {
	// 检查文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 读取文件内容
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析JSON
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 验证必要的配置项
	if config.Addr == "" {
		return nil, fmt.Errorf("服务器地址不能为空")
	}
	config.Addr = normalizePanelAddr(config.Addr)

	return &config, nil
}

func normalizePanelAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if idx := strings.Index(addr, "://"); idx >= 0 {
		scheme := strings.ToLower(addr[:idx])
		rest := addr[idx+3:]
		if cut := strings.IndexAny(rest, "/?#"); cut >= 0 {
			rest = rest[:cut]
		}
		return scheme + "://" + rest
	}
	if idx := strings.IndexAny(addr, "/?#"); idx >= 0 {
		addr = addr[:idx]
	}
	return addr
}
