//go:build windows

package client

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Windows DPAPI：密钥/凭证用当前用户凭据加密落盘。
// 拷到别的机器或别的用户下解不开，重装系统后也解不开——这正是「一设备一凭证」应有的样子。

var (
	crypt32DLL  = syscall.NewLazyDLL("crypt32.dll")
	kernel32DLL = syscall.NewLazyDLL("kernel32.dll")

	procCryptProtectData   = crypt32DLL.NewProc("CryptProtectData")
	procCryptUnprotectData = crypt32DLL.NewProc("CryptUnprotectData")
	procLocalFree          = kernel32DLL.NewProc("LocalFree")
)

const cryptProtectUIForbidden = 0x1

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func blobOf(b []byte) *dataBlob {
	if len(b) == 0 {
		return &dataBlob{}
	}
	return &dataBlob{cbData: uint32(len(b)), pbData: &b[0]}
}

func protectSecret(plain, entropy []byte) ([]byte, error) {
	in := blobOf(plain)
	ent := blobOf(entropy)
	var out dataBlob
	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(in)),
		0,
		uintptr(unsafe.Pointer(ent)),
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("DPAPI 加密失败: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	res := make([]byte, out.cbData)
	copy(res, unsafe.Slice(out.pbData, out.cbData))
	return res, nil
}

func unprotectSecret(cipher, entropy []byte) ([]byte, error) {
	in := blobOf(cipher)
	ent := blobOf(entropy)
	var out dataBlob
	r, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(in)),
		0,
		uintptr(unsafe.Pointer(ent)),
		0,
		0,
		cryptProtectUIForbidden,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("DPAPI 解密失败（可能不是同一台机器或同一用户）: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	res := make([]byte, out.cbData)
	copy(res, unsafe.Slice(out.pbData, out.cbData))
	return res, nil
}
