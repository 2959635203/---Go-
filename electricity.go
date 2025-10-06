package main

import (
	"database/sql"
	"encoding/json"
	Cookie "fit-electricity/WangXiaoCookie"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// 全局变量
var (
	roomData map[string]map[string][]struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	db *sql.DB

	// Cookie 管理
	cookieManager = &CookieManager{
		cookie:     "",
		mu:         &sync.RWMutex{},
		updateCond: sync.NewCond(&sync.Mutex{}),
		isUpdating: false,
		updateFlag: false,
	}

	// 数据库连接池设置
	dbMutex sync.RWMutex
)

// CookieManager 管理全局唯一的Cookie
type CookieManager struct {
	cookie     string
	mu         *sync.RWMutex
	updateCond *sync.Cond
	isUpdating bool
	updateFlag bool
}

// GetCookie 获取当前Cookie
func (cm *CookieManager) GetCookie() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.cookie
}

// UpdateCookie 更新Cookie
func (cm *CookieManager) UpdateCookie(workerID int) error {
	// 获取更新锁
	cm.updateCond.L.Lock()

	// 如果已经在更新，等待完成
	if cm.isUpdating {
		log.Printf("工作线程%d: 检测到其他线程正在更新Cookie，等待...", workerID)
		for cm.isUpdating {
			cm.updateCond.Wait()
		}
		cm.updateCond.L.Unlock()
		log.Printf("工作线程%d: Cookie更新已完成，继续执行", workerID)
		return nil
	}

	// 设置更新状态
	cm.isUpdating = true
	cm.updateFlag = false
	cm.updateCond.L.Unlock()

	// 执行更新
	var err error
	defer func() {
		// 更新完成，释放锁并通知等待的线程
		cm.updateCond.L.Lock()
		cm.isUpdating = false
		cm.updateCond.L.Unlock()
		cm.updateCond.Broadcast()
	}()

	// 获取新Cookie
	log.Printf("工作线程%d: 开始获取新Cookie...", workerID)
	newCookie, err := Cookie.GetWanXiaoCookie()
	if err != nil {
		return fmt.Errorf("获取Cookie失败: %v", err)
	}

	// 验证Cookie是否有效
	if !cm.validateCookie(newCookie) {
		return fmt.Errorf("获取的Cookie无效")
	}

	// 更新Cookie
	cm.mu.Lock()
	cm.cookie = newCookie
	cm.mu.Unlock()

	// 显示更新后的Cookie（只显示关键部分）
	cookieParts := strings.Split(newCookie, ";")
	var importantParts []string
	for _, part := range cookieParts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "sid=") || strings.Contains(part, "SESSION=") {
			importantParts = append(importantParts, part)
		}
	}

	log.Printf("工作线程%d: Cookie更新成功: %s", workerID, strings.Join(importantParts, "; "))
	return nil
}

// 验证Cookie是否有效 - 只检查sid和SESSION字段
func (cm *CookieManager) validateCookie(cookie string) bool {
	if cookie == "" {
		return false
	}

	// 只检查必要的字段：sid和SESSION
	requiredFields := []string{"sid", "SESSION"}
	for _, field := range requiredFields {
		if !strings.Contains(cookie, field) {
			log.Printf("Cookie缺少必要字段: %s", field)
			return false
		}
	}

	return true
}

// WaitForCookieUpdate 等待Cookie更新完成
func (cm *CookieManager) WaitForCookieUpdate() {
	cm.updateCond.L.Lock()
	for cm.isUpdating {
		cm.updateCond.Wait()
	}
	cm.updateCond.L.Unlock()
}

// 标记需要更新
func (cm *CookieManager) MarkForUpdate() bool {
	cm.updateCond.L.Lock()
	defer cm.updateCond.L.Unlock()

	if cm.isUpdating || cm.updateFlag {
		return false
	}

	cm.updateFlag = true
	return true
}

// 初始化函数
func init() {
	log.Println("正在初始化系统...")

	// 初始化数据库
	if err := initDatabase(); err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}

	// 加载房间数据
	if err := loadRoomData(); err != nil {
		log.Fatalf("房间数据加载失败: %v", err)
	}

	log.Println("系统初始化完成")
}

// 初始化数据库
func initDatabase() error {
	var err error
	db, err = sql.Open("sqlite", "./electricity.db?_busy_timeout=10000&_journal_mode=WAL&_sync=NORMAL&cache=shared")
	if err != nil {
		return fmt.Errorf("打开数据库失败: %v", err)
	}

	// 设置连接池参数
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	// 测试数据库连接
	if err := db.Ping(); err != nil {
		return fmt.Errorf("数据库连接失败: %v", err)
	}

	// 检查并创建表
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS electricity_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			room TEXT NOT NULL,
			timestamp DATETIME NOT NULL,
			elect REAL NOT NULL,
			UNIQUE(room, timestamp)
		);
		CREATE INDEX IF NOT EXISTS idx_room_timestamp ON electricity_records(room, timestamp);
	`)
	if err != nil {
		return fmt.Errorf("创建表失败: %v", err)
	}

	log.Println("数据库初始化完成")
	return nil
}

// ConvertRoomCode 将楼栋-房间号转换为完整房间ID
func ConvertRoomCode(roomCode string) (string, error) {
	parts := strings.Split(roomCode, "-")
	if len(parts) < 2 {
		return "", fmt.Errorf("无效的房间格式: %s", roomCode)
	}

	building := parts[0]
	roomNumber := parts[1]

	buildingData, exists := roomData[building]
	if !exists {
		return "", fmt.Errorf("楼栋不存在: %s", building)
	}

	// 搜索所有楼层
	for _, rooms := range buildingData {
		for _, room := range rooms {
			if room.Name == roomNumber {
				return room.ID, nil
			}
		}
	}

	return "", fmt.Errorf("房间号未找到: %s 在楼栋 %s", roomNumber, building)
}

// 获取最优工作线程数
func getOptimalWorkerCount() int {
	// 获取CPU核心数
	cpuCores := runtime.NumCPU()

	// 对于I/O密集型任务，可以使用更多的goroutine
	workerCount := cpuCores * 4

	// 设置最小和最大限制
	if workerCount < 4 {
		workerCount = 4
	}
	if workerCount > 32 {
		workerCount = 32
	}

	log.Printf("检测到 %d CPU核心，设置 %d 个工作线程", cpuCores, workerCount)
	return workerCount
}

// RunDailyElectricityQuery 每日查询并写入数据库
func RunDailyElectricityQuery() {
	log.Println("开始执行每日电量查询...")
	startTime := time.Now()

	// 先确保有有效的Cookie
	if cookieManager.GetCookie() == "" {
		log.Println("初始Cookie为空，尝试获取Cookie...")
		if err := cookieManager.UpdateCookie(0); err != nil {
			log.Printf("初始Cookie获取失败: %v", err)
			return
		}
	}

	roomCodes := getAllRoomCodes()
	log.Printf("共有 %d 个房间需要查询", len(roomCodes))

	currentTime := time.Now()
	today := currentTime.Format("2006-01-02")

	// 获取工作线程数
	workerCount := getOptimalWorkerCount()

	// 创建任务通道和结果通道
	taskChan := make(chan string, len(roomCodes))
	resultChan := make(chan *queryResult, len(roomCodes))

	// 使用信号量控制并发数
	semaphore := make(chan struct{}, workerCount)

	// 启动工作线程
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go worker(i, taskChan, resultChan, &wg, today, semaphore)
	}

	// 发送任务到通道
	for _, roomCode := range roomCodes {
		taskChan <- roomCode
	}
	close(taskChan)

	// 等待所有工作线程完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 处理结果
	successCount := 0
	failureCount := 0
	totalCount := len(roomCodes)

	for result := range resultChan {
		if result.success {
			successCount++
			if successCount%100 == 0 {
				log.Printf("进度: %d/%d", successCount, totalCount)
			}
		} else {
			failureCount++
			log.Printf("查询失败: %s - %v", result.roomCode, result.err)
		}
	}

	// 计算总耗时
	duration := time.Since(startTime)
	log.Printf("查询完成: 成功 %d, 失败 %d, 总计 %d, 耗时: %v",
		successCount, failureCount, totalCount, duration)
}

// 查询结果结构
type queryResult struct {
	roomCode    string
	electricity string
	success     bool
	err         error
}

// 工作线程
func worker(id int, taskChan <-chan string, resultChan chan<- *queryResult, wg *sync.WaitGroup, today string, semaphore chan struct{}) {
	defer wg.Done()

	for roomCode := range taskChan {
		// 获取信号量，控制并发
		semaphore <- struct{}{}

		fullRoomID, err := ConvertRoomCode(roomCode)
		if err != nil {
			resultChan <- &queryResult{roomCode: roomCode, success: false, err: err}
			<-semaphore
			continue
		}

		// 检查今天是否已查询过
		dbMutex.RLock()
		var count int
		err = db.QueryRow(`
			SELECT COUNT(*) FROM electricity_records 
			WHERE room = ? AND date(timestamp) = ?
		`, fullRoomID, today).Scan(&count)
		dbMutex.RUnlock()

		if err != nil {
			resultChan <- &queryResult{roomCode: roomCode, success: false, err: fmt.Errorf("数据库查询失败: %v", err)}
			<-semaphore
			continue
		}

		if count > 0 {
			resultChan <- &queryResult{roomCode: roomCode, success: true, electricity: "已存在"}
			<-semaphore
			continue
		}

		// 查询电量
		electricity, err := queryElectricityWithRetry(fullRoomID, roomCode, id)
		if err != nil {
			resultChan <- &queryResult{roomCode: roomCode, success: false, err: err}
			<-semaphore
			continue
		}

		// 写入数据库
		dbMutex.Lock()
		stmt, err := db.Prepare("INSERT OR IGNORE INTO electricity_records (room, timestamp, elect) VALUES (?, ?, ?)")
		if err != nil {
			dbMutex.Unlock()
			resultChan <- &queryResult{roomCode: roomCode, success: false, err: fmt.Errorf("准备SQL语句失败: %v", err)}
			<-semaphore
			continue
		}

		_, err = stmt.Exec(fullRoomID, time.Now(), electricity)
		stmt.Close()
		dbMutex.Unlock()

		if err != nil {
			resultChan <- &queryResult{roomCode: roomCode, success: false, err: fmt.Errorf("写入数据库失败: %v", err)}
			<-semaphore
			continue
		}

		resultChan <- &queryResult{
			roomCode:    roomCode,
			electricity: electricity,
			success:     true,
		}

		// 释放信号量
		<-semaphore

		// 查询间隔
		time.Sleep(100 * time.Millisecond)
	}
}

// 检查是否为Cookie失效错误
func isCookieExpiredError(responseBody string) bool {
	return strings.Contains(responseBody, "系统繁忙，请稍后重试") ||
		strings.Contains(responseBody, "RspBaseVO") ||
		strings.Contains(responseBody, "登录")
}

// 带重试的电量查询（简化版）
func queryElectricityWithRetry(room, roomCode string, workerID int) (string, error) {
	const maxRetries = 3

	for i := 0; i < maxRetries; i++ {
		// 获取当前Cookie
		cookie := cookieManager.GetCookie()

		// 查询电量
		electricity, responseBody := getElectricity(room, cookie)
		if electricity != "" {
			return electricity, nil
		}

		// 查询失败，检查错误类型
		log.Printf("房间 %s (工作线程%d): 第%d次查询失败，服务器返回: %s", roomCode, workerID, i+1, responseBody)

		// 判断是否为Cookie失效错误
		if isCookieExpiredError(responseBody) {
			log.Printf("房间 %s (工作线程%d): 检测到Cookie失效，尝试更新Cookie", roomCode, workerID)

			// 直接更新Cookie
			if err := cookieManager.UpdateCookie(workerID); err != nil {
				log.Printf("房间 %s (工作线程%d): 更新Cookie失败: %v", roomCode, workerID, err)
			}
		}

		// 如果不是最后一次重试，等待一段时间
		if i < maxRetries-1 {
			waitTime := time.Duration(i+1) * time.Second
			log.Printf("房间 %s (工作线程%d): 等待%d秒后重试", roomCode, workerID, i+1)
			time.Sleep(waitTime)
		}
	}

	return "", fmt.Errorf("电量查询失败，已达到最大重试次数(3次)")
}

// GetElectricityInfo 获取电量信息
func GetElectricityInfo(room string) (map[string]interface{}, error) {
	dbMutex.RLock()
	defer dbMutex.RUnlock()

	var elect float64
	var timestamp time.Time

	err := db.QueryRow(`
		SELECT elect, timestamp 
		FROM electricity_records 
		WHERE room = ? 
		ORDER BY timestamp DESC 
		LIMIT 1
	`, room).Scan(&elect, &timestamp)

	if err != nil {
		return nil, fmt.Errorf("未找到房间电量记录: %v", err)
	}

	result := map[string]interface{}{
		"room":        room,
		"electricity": elect,
		"time":        timestamp.Format("2006-01-02 15:04:05"),
	}

	// 计算充值信息
	rechargeInfo, err := calculateRechargeInfo(room)
	if err == nil && rechargeInfo != nil {
		result["recharge_amount"] = rechargeInfo["recharge_amount"]
		result["used_electricity"] = rechargeInfo["used_electricity"]
		result["is_recharge_day"] = rechargeInfo["is_recharge_day"]
	}

	return result, nil
}

// 实时计算充值信息
func calculateRechargeInfo(room string) (map[string]interface{}, error) {
	// 获取最近4条记录用于计算
	rows, err := db.Query(`
		SELECT timestamp, elect 
		FROM electricity_records 
		WHERE room = ? 
		ORDER BY timestamp DESC 
		LIMIT 4
	`, room)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []struct {
		Timestamp time.Time
		Elect     float64
	}

	for rows.Next() {
		var record struct {
			Timestamp time.Time
			Elect     float64
		}
		err := rows.Scan(&record.Timestamp, &record.Elect)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	if len(records) < 3 {
		return nil, fmt.Errorf("数据不足，需要至少3条记录")
	}

	// 按时间排序（从旧到新）
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.Before(records[j].Timestamp)
	})

	// 计算平均每日用电量
	var totalUsage float64
	validPairs := 0

	for i := 0; i < len(records)-1; i++ {
		usage := records[i].Elect - records[i+1].Elect
		if usage > 0 {
			// 计算相对变化率
			changeRate := usage / records[i+1].Elect
			// 允许最大100%的日变化率
			if changeRate < 1.0 {
				totalUsage += usage
				validPairs++
			} else {
				log.Printf("检测到异常用电量变化: %.2f -> %.2f (变化率: %.2f%%)",
					records[i+1].Elect, records[i].Elect, changeRate*100)
			}
		}
	}

	if validPairs == 0 {
		// 如果没有有效数据对，使用简单的平均值
		for i := 0; i < len(records)-1; i++ {
			usage := records[i].Elect - records[i+1].Elect
			if usage > 0 {
				totalUsage += usage
				validPairs++
			}
		}

		if validPairs == 0 {
			return nil, fmt.Errorf("无法计算有效平均用电量")
		}
	}

	avgUsage := totalUsage / float64(validPairs)

	// 检查最新记录是否可能充值
	latest := records[len(records)-1]
	prev := records[len(records)-2]

	// 如果电量突然大幅增加，判断为充值
	if latest.Elect > prev.Elect {
		// 使用公式计算充值电量
		rechargeElectricity := math.Ceil(latest.Elect - (prev.Elect - avgUsage))

		// 确保充值电量为正值
		if rechargeElectricity <= 0 {
			rechargeElectricity = latest.Elect - prev.Elect
		}

		// 计算实际用电量
		actualUsage := prev.Elect - (latest.Elect - rechargeElectricity)

		// 确保实际用电量为正值
		if actualUsage < 0 {
			actualUsage = avgUsage
		}

		// 计算充值金额（0.5元/度）
		rechargeAmount := rechargeElectricity * 0.5

		return map[string]interface{}{
			"recharge_amount":  rechargeAmount,
			"used_electricity": actualUsage,
			"is_recharge_day":  true,
		}, nil
	}

	// 没有充值，计算正常用电量
	if len(records) >= 2 {
		latest := records[len(records)-1]
		prev := records[len(records)-2]
		normalUsage := prev.Elect - latest.Elect

		// 确保用电量为正值
		if normalUsage < 0 {
			normalUsage = 0
		}

		return map[string]interface{}{
			"recharge_amount":  0,
			"used_electricity": normalUsage,
			"is_recharge_day":  false,
		}, nil
	}

	return nil, fmt.Errorf("无法计算用电信息")
}

// 内部函数 - 加载房间数据
func loadRoomData() error {
	file, err := os.Open("room_id.json")
	if err != nil {
		return fmt.Errorf("无法打开房间数据文件: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("读取房间数据失败: %v", err)
	}

	err = json.Unmarshal(data, &roomData)
	if err != nil {
		return fmt.Errorf("解析房间数据失败: %v", err)
	}

	log.Printf("房间数据加载完成，共加载 %d 个楼栋", len(roomData))
	return nil
}

// 内部函数 - 获取所有房间代码
func getAllRoomCodes() []string {
	var roomCodes []string
	for building, floors := range roomData {
		for _, rooms := range floors {
			for _, room := range rooms {
				if len(room.Name) == 3 {
					roomCodes = append(roomCodes, fmt.Sprintf("%s-%s", building, room.Name))
				}
			}
		}
	}
	return roomCodes
}

// 内部函数 - 实际获取电量的HTTP请求
func getElectricity(room string, cookie string) (string, string) {
	url := "https://h5cloud.17wanxiao.com:18443/CloudPayment/user/getRoomState.do?payProId=4618&schoolcode=3120&businesstype=2&roomverify=" + room
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("User-Agent", "Mozilla/5.0 (Linux; Android 12; DCO-AL00 Build/V417IR; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/95.0.4638.74 Safari/537.36 Wanxiao/5.8.6")
	req.Header.Add("Referer", "https://h5cloud.17wanxiao.com:18443/CloudPayment/bill/selectPayProject.do?txcode=2&interurl=substituted_pay&payProId=4618&amtflag=0&payamt=100&payproname=%E7%94%A8%E7%94%B5%E6%94%AF%E5%87%BA&img=https://payicons.59wanmei.com/cloudpayment/images/project/img-nav_2.png&subPayProId=")
	req.Header.Add("Cookie", cookie)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	res, err := client.Do(req)
	if err != nil {
		log.Printf("HTTP请求失败: %v", err)
		return "", fmt.Sprintf("HTTP请求失败: %v", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("读取响应失败: %v", err)
		return "", fmt.Sprintf("读取响应失败: %v", err)
	}

	responseBody := string(body)
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		log.Printf("解析JSON失败: %v", err)
		return "", responseBody
	}

	if returnCode, ok := data["returncode"].(string); ok && returnCode == "100" {
		if quantity, ok := data["quantity"].(string); ok {
			return quantity, responseBody
		}
	}

	return "", responseBody
}

// 关闭数据库连接
func CloseDB() {
	if db != nil {
		db.Close()
	}
}
