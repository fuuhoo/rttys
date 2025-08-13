/* SPDX-License-Identifier: MIT */
/*
 * Author: Jianhui Zhao <zhaojh329@gmail.com>
 */

package utils

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlD3gpKyrZTHABfpgOkD+
Nr+lgLbLNEmguiDBHwgM3v/ia4EEaSClyxBUtnanTPkXHch+FtvQ4Dt93A4SgNoE
hg43Iw6nUYhje+VQLfws189JbsniKZwXeRU+bDaRfmZkg/c26Gm0UH+S2kq4K5em
pfnFamfcLcdM+4eANAYvzTV7uSTZRZKod9eSj2qMON8Zpxy8mDWpYCs5SS/Olz9S
3OIwRhiq6bPHp3f+Gl/KNqKtBBL7VPl3AquL8mut+BE6RbRo2PQMl2jdujnziKIw
GXwIcM3qMkEWN1W2unDl9PkgIbOuRWH0f56iQy0LAyhD6e6rwe38ZtSrQVYkWmSF
QwIDAQAB
-----END PUBLIC KEY-----`

var tokenCache sync.Map

type cacheItem struct {
	user   string
	expire int64 // 过期时间戳(秒)
}

func GenUniqueID() string {
	hash := md5.Sum([]byte(uuid.New().String()))
	return hex.EncodeToString(hash[:16])
}

func ParseTLV(data []byte) map[uint8][]byte {
	if len(data) < 3 {
		return nil
	}

	tlvs := map[uint8][]byte{}

	reader := bytes.NewReader(data)

	for reader.Len() > 0 {
		typ, _ := reader.ReadByte()

		var length uint16
		err := binary.Read(reader, binary.BigEndian, &length)
		if err != nil {
			return nil
		}

		value := make([]byte, length)

		_, err = io.ReadFull(reader, value)
		if err != nil {
			return nil
		}

		tlvs[typ] = value
	}

	return tlvs
}

// 实现 RequestUtil.getValueByName 功能
func GetValueByName(c *gin.Context, name string) string {
	// 1. 尝试从Cookie中获取
	cookie, err := c.Cookie(name)
	if err == nil && cookie != "" {
		return cookie
	}
	// 2. 尝试从Header中获取
	if value := c.GetHeader(name); value != "" {
		return value
	}
	return ""
}

func ValidateToken(tokenString string) (string, int64, error) {
	// 解析RSA公钥
	pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
	if err != nil {
		return "", 0, fmt.Errorf("密钥解析失败: %w", err)
	}
	// 解析并验证Token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("不支持的签名算法: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		return "", 0, err
	}

	// 提取声明信息
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// 获取用户标识
		user, ok := claims["sub"].(string)
		if !ok || user == "" {
			return "", 0, errors.New("无效的用户标识")
		}

		// 获取过期时间
		exp, ok := claims["exp"].(float64)
		if !ok {
			return "", 0, errors.New("缺少过期时间")
		}

		return user, int64(exp), nil
	}

	return "", 0, errors.New("无效的token声明")
}

func ValidateCasbin(tokenString string) bool {
	return true
}

func GetFromCache(token string) (string, bool) {
	if item, ok := tokenCache.Load(token); ok {
		cacheItem := item.(*cacheItem)
		if time.Now().Unix() < cacheItem.expire {
			return cacheItem.user, true
		}
		// 清理过期token
		tokenCache.Delete(token)
	}
	return "", false
}

func CheckPermission(address string, body map[string]string) (bool, string, error) {

	formData := url.Values{}
	for k, v := range body {
		formData.Add(k, v)
	}

	encodedData := formData.Encode() // 编码为字符串

	// 创建带超时的HTTP客户端
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	req, err := http.NewRequest("POST", address+"/swadmin/permission/ifApiPermit", bytes.NewBufferString(encodedData))
	if err != nil {
		return false, "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("请求权限服务失败")
	}
	defer resp.Body.Close()

	// 读取响应体
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("读取响应失败: %w", err)
	}
	respBody := buf.String()

	return resp.StatusCode == http.StatusOK, respBody, nil
}

// 设置缓存
func SetCache(token, user string, ttl int64) {
	expireTime := time.Now().Unix() + ttl
	tokenCache.Store(token, &cacheItem{
		user:   user,
		expire: expireTime,
	})
}
