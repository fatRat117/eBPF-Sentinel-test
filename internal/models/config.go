package models

import (
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	WhitelistTypeIP       = "ip"
	WhitelistTypePort     = "port"
	WhitelistTypeExecPath = "exec_path"
)

// UserConfig stores persisted runtime settings, such as monitoring switches
// and alert thresholds.
type UserConfig struct {
	Key       string    `json:"key" gorm:"primaryKey;size:128"`
	Value     string    `json:"value" gorm:"type:text"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WhitelistRule stores user-managed trusted rules. IP/port rules are synced to
// network eBPF maps, while exec_path rules suppress derived execve alerts.
type WhitelistRule struct {
	ID        uint64    `json:"id" gorm:"primaryKey"`
	RuleType  string    `json:"type" gorm:"column:type;size:32;uniqueIndex:idx_whitelist_type_value"`
	Value     string    `json:"value" gorm:"size:512;uniqueIndex:idx_whitelist_type_value"`
	Enabled   bool      `json:"enabled" gorm:"default:true"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (WhitelistRule) TableName() string {
	return "whitelist_rules"
}

func UpsertUserConfig(key, value string) error {
	if DB == nil {
		return errors.New("database is not initialized")
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("config key is empty")
	}
	record := &UserConfig{Key: key, Value: value}
	return DB.Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(record).Error
}

func GetUserConfig(key string) (string, bool, error) {
	if DB == nil {
		return "", false, errors.New("database is not initialized")
	}
	var record UserConfig
	result := DB.Limit(1).Find(&record, "key = ?", strings.TrimSpace(key))
	if result.Error != nil {
		return "", false, result.Error
	}
	if result.RowsAffected == 0 {
		return "", false, nil
	}
	return record.Value, true, nil
}

func CreateWhitelistRule(rule *WhitelistRule) error {
	if DB == nil {
		return errors.New("database is not initialized")
	}
	if rule == nil {
		return errors.New("whitelist rule is nil")
	}
	return DB.Create(rule).Error
}

func GetWhitelistRule(id uint64) (*WhitelistRule, error) {
	if DB == nil {
		return nil, errors.New("database is not initialized")
	}
	var rule WhitelistRule
	result := DB.Limit(1).Find(&rule, id)
	if result.Error != nil {
		return nil, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	return &rule, nil
}

func FindWhitelistRule(ruleType, value string) (*WhitelistRule, bool, error) {
	if DB == nil {
		return nil, false, errors.New("database is not initialized")
	}
	var rule WhitelistRule
	result := DB.Limit(1).Find(&rule, "type = ? AND value = ?", ruleType, value)
	if result.Error != nil {
		return nil, false, result.Error
	}
	if result.RowsAffected == 0 {
		return nil, false, nil
	}
	return &rule, true, nil
}

func ListWhitelistRules(ruleType string, includeDisabled bool) ([]WhitelistRule, error) {
	if DB == nil {
		return nil, errors.New("database is not initialized")
	}
	query := DB.Order("type asc, value asc")
	if strings.TrimSpace(ruleType) != "" {
		query = query.Where("type = ?", strings.TrimSpace(ruleType))
	}
	if !includeDisabled {
		query = query.Where("enabled = ?", true)
	}
	var rules []WhitelistRule
	result := query.Find(&rules)
	return rules, result.Error
}

func UpdateWhitelistRule(rule *WhitelistRule) error {
	if DB == nil {
		return errors.New("database is not initialized")
	}
	if rule == nil {
		return errors.New("whitelist rule is nil")
	}
	return DB.Save(rule).Error
}

func DeleteWhitelistRule(id uint64) error {
	if DB == nil {
		return errors.New("database is not initialized")
	}
	return DB.Delete(&WhitelistRule{}, id).Error
}
