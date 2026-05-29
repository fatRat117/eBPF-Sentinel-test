package main

import (
	"crypto/subtle"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

const adminTokenEnv = "THIS_IS_MY_OWN_TOKEN"

// requireMutationAccess keeps control-plane endpoints local by default.
// Remote writes require an explicit bearer token configured at process start.
func requireMutationAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		if isLoopbackRequest(c.Request) || hasAdminToken(c.Request) {
			c.Next()
			return
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error": "mutation endpoints require loopback access or SENTINEL_ADMIN_TOKEN",
		})
	}
}

func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func hasAdminToken(r *http.Request) bool {
	expected := os.Getenv(adminTokenEnv)
	if expected == "" {
		return false
	}

	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if token == "" {
		token = strings.TrimSpace(r.Header.Get("X-Sentinel-Token"))
	}
	if len(token) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}
