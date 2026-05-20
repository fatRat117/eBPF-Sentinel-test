package main

import (
	"net/http"
	"strconv"

	"github.com/ebpf-sentinel/internal/models"
	"github.com/ebpf-sentinel/internal/plugin"
	"github.com/gin-gonic/gin"
)

type whitelistRulePayload struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Enabled *bool  `json:"enabled"`
}

func registerWhitelistRoutes(r *gin.Engine, networkPlugin *plugin.NetworkPlugin, execPolicy *execPathWhitelistPolicy) {
	r.GET("/api/whitelist", func(c *gin.Context) {
		ruleType := c.Query("type")
		if ruleType != "" {
			normalizedType, err := normalizeWhitelistType(ruleType)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid whitelist type"})
				return
			}
			ruleType = normalizedType
		}

		enabledOnly, _ := strconv.ParseBool(c.Query("enabled_only"))
		rules, err := models.ListWhitelistRules(ruleType, !enabledOnly)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, rules)
	})

	r.POST("/api/whitelist", requireMutationAccess(), func(c *gin.Context) {
		var payload whitelistRulePayload
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid whitelist payload"})
			return
		}

		ruleType, value, err := normalizeWhitelistRule(payload.Type, payload.Value)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if existing, found, err := models.FindWhitelistRule(ruleType, value); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		} else if found {
			c.JSON(http.StatusConflict, gin.H{"error": "Whitelist rule already exists", "rule": existing})
			return
		}

		enabled := true
		if payload.Enabled != nil {
			enabled = *payload.Enabled
		}
		rule := &models.WhitelistRule{
			RuleType: ruleType,
			Value:    value,
			Enabled:  enabled,
		}
		if err := createWhitelistRuleConsistent(networkPlugin, execPolicy, rule); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "rule": rule})
			return
		}
		c.JSON(http.StatusCreated, rule)
	})

	r.PATCH("/api/whitelist/:id", requireMutationAccess(), func(c *gin.Context) {
		id, err := strconv.ParseUint(c.Param("id"), 10, 64)
		if err != nil || id == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid whitelist rule ID"})
			return
		}
		oldRule, err := models.GetWhitelistRule(id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Whitelist rule not found"})
			return
		}

		var payload whitelistRulePayload
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid whitelist payload"})
			return
		}

		nextType := oldRule.RuleType
		if payload.Type != "" {
			nextType = payload.Type
		}
		nextValue := oldRule.Value
		if payload.Value != "" {
			nextValue = payload.Value
		}
		nextType, nextValue, err = normalizeWhitelistRule(nextType, nextValue)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if existing, found, err := models.FindWhitelistRule(nextType, nextValue); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		} else if found && existing.ID != oldRule.ID {
			c.JSON(http.StatusConflict, gin.H{"error": "Whitelist rule already exists", "rule": existing})
			return
		}

		updated := *oldRule
		updated.RuleType = nextType
		updated.Value = nextValue
		if payload.Enabled != nil {
			updated.Enabled = *payload.Enabled
		}
		if err := updateWhitelistRuleConsistent(networkPlugin, execPolicy, oldRule, &updated); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "rule": updated})
			return
		}
		c.JSON(http.StatusOK, updated)
	})

	r.DELETE("/api/whitelist/:id", requireMutationAccess(), func(c *gin.Context) {
		id, err := strconv.ParseUint(c.Param("id"), 10, 64)
		if err != nil || id == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid whitelist rule ID"})
			return
		}
		oldRule, err := models.GetWhitelistRule(id)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Whitelist rule not found"})
			return
		}
		if err := deleteWhitelistRuleConsistent(networkPlugin, execPolicy, oldRule); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"deleted": true, "id": id})
	})
}
