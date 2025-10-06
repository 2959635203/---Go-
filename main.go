package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// API处理函数
func handleGetElectricity(w http.ResponseWriter, r *http.Request) {
	// 设置响应头
	w.Header().Set("Content-Type", "application/json")

	// 解析参数
	room := r.URL.Query().Get("room")
	isRealTimeStr := r.URL.Query().Get("isRealTime")

	// 参数验证
	if room == "" {
		sendErrorResponse(w, "参数room不能为空")
		return
	}

	// 转换房间号
	fullRoomID, err := ConvertRoomCode(room)
	if err != nil {
		sendErrorResponse(w, err.Error())
		return
	}

	// 处理实时查询
	if isRealTimeStr == "1" {
		// 实时查询电量
		electricity, err := queryElectricityWithRetry(fullRoomID, room, 0)
		if err != nil {
			sendErrorResponse(w, fmt.Sprintf("实时查询失败: %v", err))
			return
		}

		// 转换为浮点数
		var electFloat float64
		fmt.Sscanf(electricity, "%f", &electFloat)

		// 返回实时数据
		sendSuccessResponse(w, electFloat, time.Now().Format("2006-01-02 15:04:05"), nil)
		return
	}

	// 从数据库查询
	info, err := GetElectricityInfo(fullRoomID, false)
	if err != nil {
		sendErrorResponse(w, err.Error())
		return
	}

	// 提取电量信息
	electricity, ok := info["electricity"].(float64)
	if !ok {
		sendErrorResponse(w, "电量数据格式错误")
		return
	}

	timeStr, ok := info["time"].(string)
	if !ok {
		sendErrorResponse(w, "时间数据格式错误")
		return
	}

	// 准备额外信息
	var extraInfo map[string]interface{}
	if rechargeAmount, exists := info["recharge_amount"]; exists {
		extraInfo = map[string]interface{}{
			"recharge_amount": rechargeAmount,
		}
	}

	sendSuccessResponse(w, electricity, timeStr, extraInfo)
}

// 发送成功响应
func sendSuccessResponse(w http.ResponseWriter, electricity float64, updateTime string, extraInfo map[string]interface{}) {
	response := map[string]interface{}{
		"status":            1,
		"remainElectricity": fmt.Sprintf("%.2f", electricity),
		"remainTime":        "未知",
		"lastUpdateTime":    updateTime,
	}

	// 添加额外信息
	if extraInfo != nil {
		for key, value := range extraInfo {
			response[key] = value
		}
	}

	json.NewEncoder(w).Encode(response)
}

// 发送错误响应
func sendErrorResponse(w http.ResponseWriter, errorMsg string) {
	response := map[string]interface{}{
		"status": 2,
		"error":  errorMsg,
	}
	json.NewEncoder(w).Encode(response)
}

// 启动定时任务
func startScheduledTask() {
	// 程序启动时立即执行一次查询
	log.Println("程序启动，立即执行一次电量查询...")
	go func() {
		// 等待一小段时间，确保服务完全启动
		time.Sleep(5 * time.Second)
		RunDailyElectricityQuery()
	}()

	// 计算到下一个凌晨1点的时间
	now := time.Now()
	next := time.Date(
		now.Year(), now.Month(), now.Day()+1,
		1, 0, 0, 0, now.Location(),
	)
	duration := next.Sub(now)

	log.Printf("首次定时任务将在 %v 后执行 (%s)", duration, next.Format("2006-01-02 15:04:05"))

	// 创建一个定时器，在下一个凌晨1点触发
	time.AfterFunc(duration, func() {
		// 执行每日查询
		log.Println("定时任务: 开始执行每日电量查询")
		RunDailyElectricityQuery()

		// 设置24小时后的下一次执行
		ticker := time.NewTicker(24 * time.Hour)
		go func() {
			for range ticker.C {
				log.Println("定时任务: 开始执行每日电量查询")
				RunDailyElectricityQuery()
			}
		}()
	})
}

// 主函数
func main() {
	defer CloseDB()

	// 启动定时任务
	startScheduledTask()

	// 设置HTTP路由
	http.HandleFunc("/api/getElectricity", handleGetElectricity)

	log.Println("电力查询服务启动在 :8080 端口")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
