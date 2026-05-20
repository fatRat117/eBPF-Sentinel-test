package models

import (
	"path/filepath"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupConfigTestDB(t *testing.T) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "sentinel-test.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := db.AutoMigrate(&UserConfig{}, &WhitelistRule{}); err != nil {
		t.Fatalf("migrate test db: %v", err)
	}
	DB = db
	t.Cleanup(func() {
		DB = nil
	})
}

func TestUserConfigUpsert(t *testing.T) {
	setupConfigTestDB(t)

	if err := UpsertUserConfig("execve_enabled", "true"); err != nil {
		t.Fatalf("upsert config: %v", err)
	}
	if err := UpsertUserConfig("execve_enabled", "false"); err != nil {
		t.Fatalf("update config: %v", err)
	}

	value, ok, err := GetUserConfig("execve_enabled")
	if err != nil {
		t.Fatalf("get config: %v", err)
	}
	if !ok || value != "false" {
		t.Fatalf("expected updated config false, got value=%q ok=%v", value, ok)
	}
}

func TestWhitelistRuleCRUD(t *testing.T) {
	setupConfigTestDB(t)

	rule := &WhitelistRule{
		RuleType: WhitelistTypeExecPath,
		Value:    "/usr/bin/chmod",
		Enabled:  true,
	}
	if err := CreateWhitelistRule(rule); err != nil {
		t.Fatalf("create whitelist rule: %v", err)
	}

	found, ok, err := FindWhitelistRule(WhitelistTypeExecPath, "/usr/bin/chmod")
	if err != nil {
		t.Fatalf("find whitelist rule: %v", err)
	}
	if !ok || found.ID == 0 {
		t.Fatalf("expected created rule, got ok=%v rule=%#v", ok, found)
	}

	found.Enabled = false
	if err := UpdateWhitelistRule(found); err != nil {
		t.Fatalf("update whitelist rule: %v", err)
	}

	enabledRules, err := ListWhitelistRules(WhitelistTypeExecPath, false)
	if err != nil {
		t.Fatalf("list enabled whitelist rules: %v", err)
	}
	if len(enabledRules) != 0 {
		t.Fatalf("expected no enabled rules, got %d", len(enabledRules))
	}

	allRules, err := ListWhitelistRules(WhitelistTypeExecPath, true)
	if err != nil {
		t.Fatalf("list all whitelist rules: %v", err)
	}
	if len(allRules) != 1 {
		t.Fatalf("expected disabled rule to remain visible, got %d", len(allRules))
	}
}
