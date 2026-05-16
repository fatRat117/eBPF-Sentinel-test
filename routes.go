package main

import (
	"net/http"
	"strconv"
	"time"

	"github.com/ebpf-sentinel/internal/models"
	"github.com/ebpf-sentinel/internal/plugin"
	"github.com/ebpf-sentinel/internal/websocket"
	"github.com/gin-gonic/gin"
)

// setupRoutes 配置Gin路由 / Configures API, WebSocket and static routes.
func setupRoutes(r *gin.Engine, hub *websocket.Hub, alertPlugin *plugin.AlertPlugin, startedAt time.Time) {
	r.GET("/api/events", func(c *gin.Context) {
		events, err := models.GetRecentEvents(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, events)
	})

	r.GET("/api/network-events", func(c *gin.Context) {
		events, err := models.GetRecentNetworkEvents(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, events)
	})

	r.GET("/api/alerts", func(c *gin.Context) {
		var (
			events []models.AlertEvent
			err    error
		)
		if includeHistory, _ := strconv.ParseBool(c.Query("history")); includeHistory {
			events, err = models.GetRecentAlertEvents(100)
		} else {
			events, err = models.GetRecentAlertEventsSince(100, startedAt)
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, events)
	})

	r.PATCH("/api/alerts/:id/status", requireMutationAccess(), func(c *gin.Context) {
		id, err := strconv.ParseUint(c.Param("id"), 10, 64)
		if err != nil || id == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert ID"})
			return
		}

		var payload struct {
			Status string `json:"status"`
		}
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid status payload"})
			return
		}
		if !isValidAlertStatus(payload.Status) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert status"})
			return
		}

		event, err := models.UpdateAlertEventStatus(id, payload.Status)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Alert not found"})
			return
		}
		c.JSON(http.StatusOK, event)
	})

	r.GET("/api/policy/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"execve_enabled":  isExecveMonitoringEnabled(),
			"network_enabled": isNetworkMonitoringEnabled(),
		})
	})

	r.GET("/api/alert/config", func(c *gin.Context) {
		if alertPlugin == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Alert plugin is not initialized"})
			return
		}
		c.JSON(http.StatusOK, alertPlugin.Config())
	})

	r.POST("/api/alert/config", requireMutationAccess(), func(c *gin.Context) {
		if alertPlugin == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Alert plugin is not initialized"})
			return
		}
		var config plugin.AlertConfig
		if err := c.ShouldBindJSON(&config); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid alert config"})
			return
		}
		if err := alertPlugin.UpdateConfig(config); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, alertPlugin.Config())
	})

	r.POST("/api/policy/execve/:enabled", requireMutationAccess(), func(c *gin.Context) {
		enabled, err := strconv.ParseBool(c.Param("enabled"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid enabled value"})
			return
		}
		if err := setExecveMonitoringEnabled(enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"execve_enabled": enabled})
	})

	r.POST("/api/policy/network/:enabled", requireMutationAccess(), func(c *gin.Context) {
		enabled, err := strconv.ParseBool(c.Param("enabled"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid enabled value"})
			return
		}
		if err := setNetworkMonitoringEnabled(enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"network_enabled": enabled})
	})

	registerProcessRoutes(r)

	r.GET("/ws", func(c *gin.Context) {
		hub.ServeWs(c.Writer, c.Request)
	})

	r.Static("/assets", "./web/dist/assets")
	r.StaticFile("/", "./web/dist/index.html")
	r.NoRoute(func(c *gin.Context) {
		c.File("./web/dist/index.html")
	})
}

func isValidAlertStatus(status string) bool {
	switch status {
	case "active", "terminated", "exited", "failed", "resolved", "ignored":
		return true
	default:
		return false
	}
}
