package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"time"
)

// 启动HTTP服务器
func startHTTPServer() {
	// 设置HTTP路由
	http.HandleFunc("/api/getElectricity", handleGetElectricity)

	log.Println("电力查询服务启动在 :8080 端口")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// API处理函数
func handleGetElectricity(w http.ResponseWriter, r *http.Request) {
	// 记录访问日志
	startTime := time.Now()
	clientIP := getClientIP(r)

	log.Printf("API访问 - 客户端IP: %s, 方法: %s, 路径: %s, 参数: %s",
		clientIP, r.Method, r.URL.Path, r.URL.RawQuery)

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	// 解析参数
	room := r.URL.Query().Get("room")
	isRealTimeStr := r.URL.Query().Get("isRealTime")

	// 参数验证
	if room == "" {
		log.Printf("API错误 - 客户端IP: %s, 错误: 参数room不能为空", clientIP)
		sendErrorResponse(w, "参数room不能为空")
		return
	}

	// 转换房间号
	fullRoomID, err := ConvertRoomCode(room)
	if err != nil {
		log.Printf("API错误 - 客户端IP: %s, 房间: %s, 错误: %v", clientIP, room, err)
		sendErrorResponse(w, err.Error())
		return
	}

	// 处理实时查询
	if isRealTimeStr == "1" {
		log.Printf("实时查询 - 客户端IP: %s, 房间: %s", clientIP, room)

		// 实时查询电量
		electricity, err := queryElectricityWithRetry(fullRoomID, room, 0)
		if err != nil {
			log.Printf("实时查询失败 - 客户端IP: %s, 房间: %s, 错误: %v", clientIP, room, err)
			sendErrorResponse(w, fmt.Sprintf("实时查询失败: %v", err))
			return
		}

		// 转换为浮点数
		var electFloat float64
		fmt.Sscanf(electricity, "%f", &electFloat)

		// 记录成功日志
		log.Printf("实时查询成功 - 客户端IP: %s, 房间: %s, 电量: %.2f", clientIP, room, electFloat)

		// 返回实时数据 - 保持JSON格式统一，不需要的字段返回NULL
		sendRealTimeResponse(w, electFloat, time.Now().Format("2006-01-02 15:04:05"))
		return
	}

	// 从数据库查询
	log.Printf("数据库查询 - 客户端IP: %s, 房间: %s", clientIP, room)
	info, err := GetElectricityInfo(fullRoomID)
	if err != nil {
		log.Printf("数据库查询失败 - 客户端IP: %s, 房间: %s, 错误: %v", clientIP, room, err)
		sendErrorResponse(w, err.Error())
		return
	}

	// 提取电量信息
	electricity, ok := info["electricity"].(float64)
	if !ok {
		log.Printf("数据格式错误 - 客户端IP: %s, 房间: %s, 错误: 电量数据格式错误", clientIP, room)
		sendErrorResponse(w, "电量数据格式错误")
		return
	}

	timeStr, ok := info["time"].(string)
	if !ok {
		log.Printf("数据格式错误 - 客户端IP: %s, 房间: %s, 错误: 时间数据格式错误", clientIP, room)
		sendErrorResponse(w, "时间数据格式错误")
		return
	}

	// 计算剩余时间
	remainTime := calculateRemainTime(fullRoomID, electricity)

	// 准备额外信息
	var rechargeAmount interface{} = nil
	if amount, exists := info["recharge_amount"]; exists {
		// 缴费金额取整
		if amountFloat, ok := amount.(float64); ok && amountFloat > 0 {
			rechargeAmount = int(math.Round(amountFloat))
			log.Printf("查询成功(含充值信息) - 客户端IP: %s, 房间: %s, 电量: %.2f, 充值金额: %d, 预测剩余时间: %s",
				clientIP, room, electricity, rechargeAmount.(int), remainTime)
		} else {
			log.Printf("查询成功 - 客户端IP: %s, 房间: %s, 电量: %.2f, 预测剩余时间: %s",
				clientIP, room, electricity, remainTime)
		}
	} else {
		log.Printf("查询成功 - 客户端IP: %s, 房间: %s, 电量: %.2f, 预测剩余时间: %s",
			clientIP, room, electricity, remainTime)
	}

	// 记录处理时间
	duration := time.Since(startTime)
	log.Printf("请求处理完成 - 客户端IP: %s, 房间: %s, 耗时: %v", clientIP, room, duration)

	// 返回完整信息 - 保持JSON格式统一
	sendFullResponse(w, electricity, timeStr, remainTime, rechargeAmount)
}

// 计算剩余使用时间
func calculateRemainTime(room string, currentElectricity float64) string {
	// 获取前一个月的用电数据来计算平均日用电量
	averageDailyUsage, err := calculateMonthlyAverageUsage(room)
	if err != nil {
		log.Printf("计算平均用电量失败 - 房间: %s, 错误: %v", room, err)
		return "未知" // 如果计算失败，返回未知
	}

	// 如果平均日用电量为0或非常小，无法计算
	if averageDailyUsage <= 0.01 {
		return "电量充足"
	}

	// 计算剩余天数
	remainingDays := currentElectricity / averageDailyUsage

	// 根据剩余天数返回不同的描述
	if remainingDays >= 30 {
		months := int(remainingDays / 30)
		return fmt.Sprintf("约%d个月", months)
	} else if remainingDays >= 7 {
		weeks := int(remainingDays / 7)
		days := int(remainingDays) % 7
		if days > 0 {
			return fmt.Sprintf("约%d周%d天", weeks, days)
		}
		return fmt.Sprintf("约%d周", weeks)
	} else if remainingDays >= 1 {
		if remainingDays < 1.5 {
			return "约1天"
		}
		return fmt.Sprintf("约%.0f天", remainingDays)
	} else {
		// 小于1天，计算小时
		remainingHours := remainingDays * 24
		if remainingHours < 1 {
			return "即将用完"
		}
		return fmt.Sprintf("约%.0f小时", remainingHours)
	}
}

// 计算月平均用电量
func calculateMonthlyAverageUsage(room string) (float64, error) {
	dbMutex.RLock()
	defer dbMutex.RUnlock()

	// 计算一个月前的日期
	oneMonthAgo := time.Now().AddDate(0, -1, 0).Format("2006-01-02")

	// 获取最近一个月的用电记录
	rows, err := db.Query(`
		SELECT timestamp, elect 
		FROM electricity_records 
		WHERE room = ? AND date(timestamp) >= ?
		ORDER BY timestamp
	`, room, oneMonthAgo)
	if err != nil {
		return 0, err
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
			return 0, err
		}
		records = append(records, record)
	}

	if len(records) < 2 {
		return 0, fmt.Errorf("数据不足，需要至少2条记录")
	}

	// 计算总用电量和总天数
	var totalUsage float64
	validPairs := 0

	// 找出有记录的天数
	daysWithRecords := make(map[string]bool)
	for _, record := range records {
		day := record.Timestamp.Format("2006-01-02")
		daysWithRecords[day] = true
	}
	totalDays := len(daysWithRecords)

	if totalDays < 2 {
		return 0, fmt.Errorf("数据天数不足，需要至少2天的数据")
	}

	// 计算用电量变化
	for i := 1; i < len(records); i++ {
		prev := records[i-1]
		current := records[i]

		// 确保时间顺序正确
		if current.Timestamp.After(prev.Timestamp) {
			usage := prev.Elect - current.Elect

			// 只考虑正常的用电情况（用电量为正且合理）
			if usage > 0 && usage < 10 { // 假设单次用电量不会超过10度
				totalUsage += usage
				validPairs++
			}
		}
	}

	if validPairs == 0 {
		return 0, fmt.Errorf("没有有效的用电数据对")
	}

	// 计算平均日用电量
	averageUsage := totalUsage / float64(totalDays)

	// 设置最小用电量阈值，避免除零错误
	if averageUsage < 0.1 {
		averageUsage = 0.1
	}

	log.Printf("房间 %s: 使用 %d 天数据计算平均日用电量: %.3f 度/天", room, totalDays, averageUsage)
	return averageUsage, nil
}

// 发送实时查询响应
func sendRealTimeResponse(w http.ResponseWriter, electricity float64, updateTime string) {
	response := map[string]interface{}{
		"status":            1,
		"remainElectricity": fmt.Sprintf("%.2f", electricity),
		"remainTime":        nil, // 实时查询不需要剩余时间，返回nil
		"lastUpdateTime":    updateTime,
		"recharge_amount":   nil, // 实时查询不需要缴费金额，返回nil
	}

	json.NewEncoder(w).Encode(response)
}

// 发送完整查询响应
func sendFullResponse(w http.ResponseWriter, electricity float64, updateTime string, remainTime string, rechargeAmount interface{}) {
	response := map[string]interface{}{
		"status":            1,
		"remainElectricity": fmt.Sprintf("%.2f", electricity),
		"remainTime":        remainTime,
		"lastUpdateTime":    updateTime,
		"recharge_amount":   rechargeAmount, // 如果有缴费金额则返回，否则为nil
	}

	json.NewEncoder(w).Encode(response)
}

// 发送错误响应
func sendErrorResponse(w http.ResponseWriter, errorMsg string) {
	response := map[string]interface{}{
		"status":            2,
		"remainElectricity": nil,
		"remainTime":        nil,
		"lastUpdateTime":    nil,
		"recharge_amount":   nil,
		"error":             errorMsg,
	}
	json.NewEncoder(w).Encode(response)
}

// 获取客户端IP
func getClientIP(r *http.Request) string {
	// 检查X-Forwarded-For头部（如果经过代理）
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return forwarded
	}

	// 检查X-Real-IP头部
	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	// 直接使用RemoteAddr
	return r.RemoteAddr
}
