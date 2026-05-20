package models

import (
	"encoding/json"
	"errors"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ExecveEvent 表示execve系统调用事件
// 当进程执行新程序时触发，记录进程创建信息
type ExecveEvent struct {
	ID          uint64    `json:"id" gorm:"primaryKey"` // 数据库自增ID
	PID         uint32    `json:"pid"`                  // 进程ID
	PPID        uint32    `json:"ppid"`                 // 父进程ID
	Comm        string    `json:"comm"`                 // 进程名（可执行文件名）
	Argv0       string    `json:"argv0"`                // 执行的命令行参数
	Whitelisted bool      `json:"whitelisted"`          // 是否命中可执行路径白名单
	CreatedAt   time.Time `json:"created_at"`           // 事件创建时间
}

// NetworkEvent 表示网络数据包事件
// 记录系统网络活动，包括TCP/UDP/ICMP流量
type NetworkEvent struct {
	ID         uint64    `json:"id" gorm:"primaryKey"` // 数据库自增ID
	PID        uint32    `json:"pid"`                  // 关联的进程ID
	SrcIP      string    `json:"src_ip"`               // 源IP地址
	DstIP      string    `json:"dst_ip"`               // 目的IP地址
	SrcPort    uint16    `json:"src_port"`             // 源端口
	DstPort    uint16    `json:"dst_port"`             // 目的端口
	Protocol   uint8     `json:"protocol"`             // 协议号（6=TCP, 17=UDP, 1=ICMP）
	Direction  uint8     `json:"direction"`            // 方向：0=入站(ingress), 1=出站(egress)
	PacketSize uint32    `json:"packet_size"`          // 数据包大小（字节）
	Comm       string    `json:"comm"`                 // 进程名
	CreatedAt  time.Time `json:"created_at"`           // 事件创建时间
}

// AlertEvent stores alerts derived from collected runtime events.
type AlertEvent struct {
	ID         uint64    `json:"id" gorm:"primaryKey"`
	RuleID     string    `json:"rule_id"`
	Severity   string    `json:"severity"`
	SourceType string    `json:"source_type"`
	Message    string    `json:"message"`
	Details    string    `json:"details"`
	Status     string    `json:"status" gorm:"default:active"`
	CreatedAt  time.Time `json:"created_at"`
}

// DB 全局数据库连接实例
var DB *gorm.DB

// InitDB 初始化SQLite数据库
// 创建数据库文件并自动迁移表结构
func InitDB() (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open("sentinel.db"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// 自动迁移表结构
	// 如果表不存在则创建，如果字段有变化则更新
	err = db.AutoMigrate(&ExecveEvent{}, &NetworkEvent{}, &AlertEvent{}, &UserConfig{}, &WhitelistRule{})
	if err != nil {
		return nil, err
	}

	DB = db
	return db, nil
}

func CreateAlertEvent(event *AlertEvent) error {
	if DB == nil {
		return errors.New("database is not initialized")
	}
	if event.Status == "" {
		event.Status = "active"
	}
	return DB.Create(event).Error
}

func UpdateAlertEventStatus(id uint64, status string) (*AlertEvent, error) {
	if DB == nil {
		return nil, errors.New("database is not initialized")
	}
	var event AlertEvent
	if err := DB.First(&event, id).Error; err != nil {
		return nil, err
	}
	event.Status = status
	if err := DB.Save(&event).Error; err != nil {
		return nil, err
	}
	return &event, nil
}

func GetRecentAlertEvents(limit int) ([]AlertEvent, error) {
	if DB == nil {
		return nil, errors.New("database is not initialized")
	}
	var events []AlertEvent
	result := DB.Order("created_at desc").Limit(limit).Find(&events)
	return events, result.Error
}

func GetRecentAlertEventsSince(limit int, since time.Time) ([]AlertEvent, error) {
	if DB == nil {
		return nil, errors.New("database is not initialized")
	}
	var events []AlertEvent
	query := DB.Order("created_at desc").Limit(limit)
	if !since.IsZero() {
		query = query.Where("created_at >= ?", since)
	}
	result := query.Find(&events)
	return events, result.Error
}

func MarshalAlertDetails(details interface{}) string {
	if details == nil {
		return "{}"
	}
	data, err := json.Marshal(details)
	if err != nil {
		return "{}"
	}
	return string(data)
}

// CreateEvent 创建新的进程事件记录
func CreateEvent(event *ExecveEvent) error {
	if DB == nil {
		return errors.New("database is not initialized")
	}
	return DB.Create(event).Error
}

// GetRecentEvents 获取最近的N条进程事件
// 按时间倒序排列，最新的在前面
func GetRecentEvents(limit int) ([]ExecveEvent, error) {
	if DB == nil {
		return nil, errors.New("database is not initialized")
	}
	var events []ExecveEvent
	result := DB.Order("created_at desc").Limit(limit).Find(&events)
	return events, result.Error
}

// CreateNetworkEvent 创建新的网络事件记录
func CreateNetworkEvent(event *NetworkEvent) error {
	if DB == nil {
		return errors.New("database is not initialized")
	}
	return DB.Create(event).Error
}

// GetRecentNetworkEvents 获取最近的N条网络事件
func GetRecentNetworkEvents(limit int) ([]NetworkEvent, error) {
	if DB == nil {
		return nil, errors.New("database is not initialized")
	}
	var events []NetworkEvent
	result := DB.Order("created_at desc").Limit(limit).Find(&events)
	return events, result.Error
}
