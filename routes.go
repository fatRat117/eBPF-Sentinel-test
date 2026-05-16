package main

import (
	"net/http"
	"strconv"

	"github.com/ebpf-sentinel/internal/models"
	"github.com/ebpf-sentinel/internal/websocket"
	"github.com/gin-gonic/gin"
)

// setupRoutes 配置Gin路由 / Configures API, WebSocket and static routes.
func setupRoutes(r *gin.Engine, hub *websocket.Hub) {
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
		events, err := models.GetRecentAlertEvents(100)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, events)
	})

	r.GET("/api/policy/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"execve_enabled":  isExecveMonitoringEnabled(),
			"network_enabled": isNetworkMonitoringEnabled(),
		})
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
