package WangXiaoCookie

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	mathRand "math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 硬编码的登录信息
var loginInfo = struct {
	PhoneNum       string
	DeviceID       string
	Password       string
	AppKey         string
	SessionID      string
	WanxiaoVersion int
	UserAgent      string
	Shebeixinghao  string
	SystemType     string
	TelephoneInfo  string
	TelephoneModel string
}{
	PhoneNum:       "18250081169",     // 请替换为你的手机号
	DeviceID:       "868410047407129", // 请替换为你的设备ID
	Password:       "2817759651sxg.",  // 请替换为你的密码
	WanxiaoVersion: 10586101,
	UserAgent:      "Dalvik/2.1.0 (Linux; U; Android 12; 23117RK66C Build/ec51c7e.0)",
	Shebeixinghao:  "raphael",
	SystemType:     "android",
	TelephoneInfo:  "12",
	TelephoneModel: "23117RK66C",
}

// GenerateRSAKey 生成RSA密钥对 - 与Python代码一致
func GenerateRSAKey(bits int) (string, string, error) {
	privateKey, err := rsa.GenerateKey(cryptoRand.Reader, bits)
	if err != nil {
		return "", "", err
	}

	// 导出私钥为PEM格式
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyPEM := string(pem.EncodeToMemory(privateKeyBlock))

	// 提取私钥部分（去掉PEM头尾）
	privateKeyStr := strings.Split(privateKeyPEM, "-----")[2]
	privateKeyStr = strings.ReplaceAll(privateKeyStr, "\n", "")

	// 导出公钥为PEM格式
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPEM := string(pem.EncodeToMemory(publicKeyBlock))

	// 提取公钥部分（去掉PEM头尾）
	publicKeyStr := strings.Split(publicKeyPEM, "-----")[2]
	publicKeyStr = strings.ReplaceAll(publicKeyStr, "\n", "")

	return publicKeyStr, privateKeyStr, nil
}

// RSADecrypt RSA解密 - 与Python代码一致（使用PKCS1v15）
func RSADecrypt(encryptedData string, privateKeyStr string) ([]byte, error) {
	// Base64解码加密数据
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("Base64解码失败: %v", err)
	}

	// 解析私钥
	privateKeyPEM := "-----BEGIN RSA PRIVATE KEY-----\n" + privateKeyStr + "\n-----END RSA PRIVATE KEY-----"
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("无法解析PEM块")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("无法解析私钥: %v", err)
	}

	// 使用PKCS1v15解密
	decryptedData, err := rsa.DecryptPKCS1v15(cryptoRand.Reader, privateKey, encryptedBytes)
	if err != nil {
		return nil, fmt.Errorf("RSA解密失败: %v", err)
	}

	return decryptedData, nil
}

// pkcs7Padding PKCS7填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// pkcs7Unpadding 去除PKCS7填充
func pkcs7Unpadding(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

// TripleDESEncrypt 3DES加密 - 与Python代码一致
func TripleDESEncrypt(plaintext, key []byte, iv string) (string, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	// PKCS7填充
	plaintext = pkcs7Padding(plaintext, block.BlockSize())

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, plaintext)

	// Base64编码
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// TripleDESDecrypt 3DES解密 - 与Python代码一致
func TripleDESDecrypt(ciphertext string, key []byte, iv string) ([]byte, error) {
	// Base64解码
	ct, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, err
	}

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ct))
	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(plaintext, ct)

	// 去除PKCS7填充
	return pkcs7Unpadding(plaintext), nil
}

// EncryptPassword 加密密码（按字符逐个加密）- 与Python代码一致
func EncryptPassword(password string, appKey string) ([]string, error) {
	iv := "66666666"
	key := []byte(appKey)

	var encryptedPasswords []string
	for _, char := range password {
		encrypted, err := TripleDESEncrypt([]byte{byte(char)}, key, iv)
		if err != nil {
			return nil, err
		}
		encryptedPasswords = append(encryptedPasswords, encrypted)
	}
	return encryptedPasswords, nil
}

// EncryptObject 加密对象 - 与Python代码一致
func EncryptObject(obj interface{}, appKey string) (string, error) {
	iv := "66666666"
	key := []byte(appKey)

	jsonData, err := json.Marshal(obj)
	if err != nil {
		return "", err
	}

	return TripleDESEncrypt(jsonData, key, iv)
}

// DecryptObject 解密对象 - 与Python代码一致
func DecryptObject(ciphertext string, appKey string) (map[string]interface{}, error) {
	iv := "66666666"
	key := []byte(appKey)

	// 去除可能的换行符
	ciphertext = strings.ReplaceAll(ciphertext, "\n", "")

	decryptedData, err := TripleDESDecrypt(ciphertext, key, iv)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(decryptedData, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// ExchangeSecret 交换密钥 - 使用与Python代码一致的实现
func ExchangeSecret() error {
	// 生成RSA密钥对
	publicKeyStr, privateKeyStr, err := GenerateRSAKey(1024)
	if err != nil {
		return fmt.Errorf("生成RSA密钥失败: %v", err)
	}

	// fmt.Printf("生成的公钥: %s\n", publicKeyStr)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	requestData := map[string]interface{}{
		"key": publicKeyStr,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return fmt.Errorf("JSON编码失败: %v", err)
	}

	// 创建请求并设置User-Agent头
	req, err := http.NewRequest("POST",
		"https://app.17wanxiao.com/campus/cam_iface46/exchangeSecretkey.action",
		bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("创建请求失败: %v", err)
	}

	req.Header.Set("User-Agent", loginInfo.UserAgent)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("服务器返回错误状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应失败: %v", err)
	}

	// 检查响应体是否为空
	if len(body) == 0 {
		return fmt.Errorf("服务器返回空响应")
	}

	// fmt.Printf("服务器原始响应: %s\n", string(body))

	// 使用RSA私钥解密响应
	decryptedData, err := RSADecrypt(string(body), privateKeyStr)
	if err != nil {
		return fmt.Errorf("RSA解密失败: %v", err)
	}

	// 检查解密后的数据
	if len(decryptedData) == 0 {
		return fmt.Errorf("解密后得到空数据")
	}

	// fmt.Printf("解密后的数据: %s\n", string(decryptedData))

	var sessionInfo struct {
		Session string `json:"session"`
		Key     string `json:"key"`
	}
	if err := json.Unmarshal(decryptedData, &sessionInfo); err != nil {
		return fmt.Errorf("JSON解析失败: %v, 原始数据: %s", err, string(decryptedData))
	}

	loginInfo.SessionID = sessionInfo.Session
	if len(sessionInfo.Key) >= 24 {
		loginInfo.AppKey = sessionInfo.Key[:24]
	} else {
		loginInfo.AppKey = sessionInfo.Key
	}

	// fmt.Printf("密钥交换成功: session=%s, appKey=%s\n", loginInfo.SessionID, loginInfo.AppKey)
	return nil
}

// GetToken 获取token - 使用与Python代码一致的实现
func GetToken() (bool, string) {
	if err := ExchangeSecret(); err != nil {
		return false, fmt.Sprintf("交换密钥失败: %v", err)
	}

	// fmt.Printf("开始登录，使用session: %s, appKey: %s\n", loginInfo.SessionID, loginInfo.AppKey)

	passwordList, err := EncryptPassword(loginInfo.Password, loginInfo.AppKey)
	if err != nil {
		return false, fmt.Sprintf("密码加密失败: %v", err)
	}
	// fmt.Printf("密码加密完成，加密后长度: %d\n", len(passwordList))

	loginArgs := map[string]interface{}{
		"appCode":        "M002",
		"deviceId":       loginInfo.DeviceID,
		"netWork":        "wifi",
		"password":       passwordList,
		"qudao":          "guanwang",
		"requestMethod":  "cam_iface46/loginnew.action",
		"shebeixinghao":  loginInfo.Shebeixinghao,
		"systemType":     loginInfo.SystemType,
		"telephoneInfo":  loginInfo.TelephoneInfo,
		"telephoneModel": loginInfo.TelephoneModel,
		"type":           "1",
		"userName":       loginInfo.PhoneNum,
		"wanxiaoVersion": loginInfo.WanxiaoVersion,
	}

	// fmt.Printf("登录参数: %+v\n", loginArgs)

	encryptedData, err := EncryptObject(loginArgs, loginInfo.AppKey)
	if err != nil {
		return false, fmt.Sprintf("参数加密失败: %v", err)
	}
	// fmt.Printf("参数加密完成，加密后数据: %s\n", encryptedData)

	uploadArgs := map[string]interface{}{
		"session": loginInfo.SessionID,
		"data":    encryptedData,
	}

	jsonData, _ := json.Marshal(uploadArgs)
	hash := sha256.Sum256(jsonData)
	signature := hex.EncodeToString(hash[:])
	// fmt.Printf("计算签名: %s\n", signature)

	jsonData, err = json.Marshal(uploadArgs)
	if err != nil {
		return false, fmt.Sprintf("JSON编码失败: %v", err)
	}

	// fmt.Printf("发送的JSON数据: %s\n", string(jsonData))

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	req, err := http.NewRequest("POST",
		"https://app.17wanxiao.com/campus/cam_iface46/loginnew.action",
		bytes.NewBuffer(jsonData))
	if err != nil {
		return false, fmt.Sprintf("创建请求失败: %v", err)
	}

	req.Header.Set("campusSign", signature)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", loginInfo.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Sprintf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	// fmt.Printf("登录响应状态码: %d\n", resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Sprintf("读取响应失败: %v", err)
	}

	// fmt.Printf("登录响应体: %s\n", string(body))

	var result struct {
		Result  bool   `json:"result_"`
		Message string `json:"message_"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return false, fmt.Sprintf("JSON解析失败: %v, 响应: %s", err, string(body))
	}

	if result.Result {
		fmt.Printf("登录成功，session: %s\n", loginInfo.SessionID)
		return true, loginInfo.SessionID
	}

	return false, fmt.Sprintf("登录失败: %s", result.Message)
}

// GetCookie 获取cookie
func GetCookie() (bool, string) {
	// 先获取token
	success, _ := GetToken()
	if !success {
		return false, "获取token失败"
	}

	// 生成随机参数
	mathRand.Seed(time.Now().UnixNano())
	customerID := mathRand.Intn(1000) + 1000

	params := url.Values{}
	params.Add("customerId", fmt.Sprintf("%d", customerID))
	params.Add("systemType", loginInfo.SystemType)
	params.Add("UAinfo", "wanxiao")
	params.Add("versioncode", fmt.Sprintf("%d", loginInfo.WanxiaoVersion))
	params.Add("token", loginInfo.SessionID)

	// 创建不自动重定向的客户端
	noRedirectClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET",
		"https://h5cloud.17wanxiao.com:18443/CloudPayment/user/pay.do?"+params.Encode(),
		nil)
	if err != nil {
		return false, ""
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Host", "h5cloud.17wanxiao.com:18443")
	req.Header.Set("User-Agent", loginInfo.UserAgent)
	req.Header.Set("X-Requested-With", "com.newcapec.mobile.ncp")

	resp, err := noRedirectClient.Do(req)
	if err != nil {
		return false, ""
	}
	defer resp.Body.Close()

	var sessionCookie string
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "SESSION" {
			sessionCookie = fmt.Sprintf("SESSION=%s", cookie.Value)
			break
		}
	}

	if sessionCookie == "" {
		return false, "未获取到SESSION cookie"
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return false, "未获取到重定向URL"
	}

	// 构建重定向URL
	baseURL := "https://h5cloud.17wanxiao.com:18443/CloudPayment/user/pay.do"
	redirectURL, err := url.Parse(baseURL)
	if err != nil {
		return false, ""
	}
	redirectURL = redirectURL.ResolveReference(&url.URL{Path: location})

	// 发送重定向请求
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 30 * time.Second,
	}

	req2, err := http.NewRequest("GET", redirectURL.String(), nil)
	if err != nil {
		return false, ""
	}

	req2.Header.Set("Cookie", sessionCookie)
	req2.Header.Set("User-Agent", loginInfo.UserAgent)

	resp2, err := client.Do(req2)
	if err != nil {
		return false, ""
	}
	defer resp2.Body.Close()

	if resp2.StatusCode == 200 {
		return true, sessionCookie + ";sid="
	}

	return false, fmt.Sprintf("重定向请求失败，状态码: %d", resp2.StatusCode)
}

// GetWanXiaoCookie 导出函数：获取完美校园Cookie
// 无需任何参数，直接返回Cookie
func GetWanXiaoCookie() (string, error) {
	success, cookie := GetCookie()
	if success {
		return cookie, nil
	}
	return "", fmt.Errorf("获取Cookie失败")
}
