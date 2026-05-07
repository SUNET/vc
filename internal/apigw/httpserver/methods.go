package httpserver

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

// sessionOrgIDs returns the org_id claim from the admin session, or nil if not present
func sessionOrgIDs(c *gin.Context) []string {
	session := sessions.Default(c)
	if v, ok := session.Get("admin_org_ids").([]string); ok {
		return v
	}
	return nil
}
