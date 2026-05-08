package httpserver

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// sessionAllowedAuthenticSources returns the allowed authentic sources from the admin session
func sessionAllowedAuthenticSources(c *gin.Context) []string {
	session := sessions.Default(c)
	if v, ok := session.Get("admin_allowed_authentic_sources").([]string); ok {
		return v
	}
	return nil
}
