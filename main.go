package main

import (
	"log"
	"time"
)

// 主函数
func main() {
	defer CloseDB()

	// 启动定时任务
	startScheduledTask()

	// 启动HTTP服务器
	startHTTPServer()
}

// 启动定时任务
func startScheduledTask() {
	/*
		// 程序启动时立即执行一次查询
		log.Println("程序启动，立即执行一次电量查询...")
		go func() {
			// 等待一小段时间，确保服务完全启动
			time.Sleep(5 * time.Second)
			RunDailyElectricityQuery()
		}()
	*/

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
