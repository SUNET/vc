package httpserver

import (
	"context"
	"net/http"
	"strings"
	"vc/pkg/model"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"

	"github.com/gin-gonic/gin"
)

func (s *Service) middlewareUserSession(ctx context.Context, cfg *model.Cfg) gin.HandlerFunc {
	store := cookie.NewStore([]byte(s.cacheService.SessionAuthKey), []byte(s.cacheService.SessionEncKey))
	store.Options(sessions.Options{
		Path:     s.sessionConfig.path,
		MaxAge:   s.sessionConfig.inactivityTimeoutInSeconds,
		Secure:   s.sessionConfig.secure,
		HttpOnly: s.sessionConfig.httpOnly,
		SameSite: s.sessionConfig.sameSite,
	})
	return sessions.Sessions(s.sessionConfig.name, store)
}

func isLogoutRoute(c *gin.Context) bool {
	path := c.Request.URL.Path
	method := c.Request.Method
	return strings.HasSuffix(path, "/logout") && method == "DELETE"
}

func (s *Service) middlewareAuthRequired(ctx context.Context) gin.HandlerFunc {
	log := s.log.New("authHandler")
	return func(c *gin.Context) {
		log.Debug("enter authRequired", "url", c.Request.URL.String(), "method", c.Request.Method)
		session := sessions.Default(c)
		username := session.Get(s.sessionConfig.usernameKey)
		if username == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized/session expired"})
			return
		}

		if !isLogoutRoute(c) {
			// Update MaxAge for the session and its cookie - extended time to expire with another x seconds defined in inactivityTimeoutInSeconds
			session.Options(sessions.Options{
				Path:     s.sessionConfig.path,
				MaxAge:   s.sessionConfig.inactivityTimeoutInSeconds,
				Secure:   s.sessionConfig.secure,
				HttpOnly: s.sessionConfig.httpOnly,
				SameSite: s.sessionConfig.sameSite,
			})

			if err := session.Save(); err != nil {
				c.JSON(500, gin.H{"error": "Could not save session"})
				return
			}
		}

		c.Next()
	}
}
