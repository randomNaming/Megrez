//go:build !windows

package client

import "fmt"

// 非 Windows 平台暂未提供系统级密钥保管，直接报错而不是悄悄降级成明文文件。
func protectSecret(plain, entropy []byte) ([]byte, error) {
	return nil, fmt.Errorf("当前平台没有可用的系统密钥保管（P0 仅支持 Windows DPAPI）")
}

func unprotectSecret(cipher, entropy []byte) ([]byte, error) {
	return nil, fmt.Errorf("当前平台没有可用的系统密钥保管（P0 仅支持 Windows DPAPI）")
}
