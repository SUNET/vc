package httphelpers

import (
	"fmt"
	"net/http"

	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/resourcereach"

	"github.com/gin-gonic/gin"
)

// resourceReachKey is the gin context key of the request's resourcereach.Reach.
const resourceReachKey = "spocp_resource_reach"

// bindResourceReach resolves what subject reaches on this request and puts it on
// the context. A failure aborts the request and returns false.
func bindResourceReach(c *gin.Context, engine *SafeEngine, service, subject string, log *logger.Log) (resourcereach.Reach, bool) {
	reach, err := resourcereach.Resolve(engine, service, c.Request.Method, c.FullPath(), subject)
	if err != nil {
		log.Error(err, "spocp_reach_failed", "req_id", c.GetString("req_id"))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization unavailable"})
		return resourcereach.Reach{}, false
	}
	c.Set(resourceReachKey, reach)
	return reach, true
}

// ResourceReachOf returns the reach the authorization middleware bound. A request
// that passed none of them is an error.
func ResourceReachOf(c *gin.Context) (resourcereach.Reach, error) {
	value, ok := c.Get(resourceReachKey)
	if !ok {
		return resourcereach.Reach{}, fmt.Errorf("context holds no %s: the route has no authorization middleware", resourceReachKey)
	}
	reach, ok := value.(resourcereach.Reach)
	if !ok {
		return resourcereach.Reach{}, fmt.Errorf("context key %s holds %T", resourceReachKey, value)
	}
	return reach, nil
}

// SelectedResourceReach returns the bound reach within the values a request names.
func SelectedResourceReach(c *gin.Context, source, scope string) (resourcereach.Reach, error) {
	reach, err := ResourceReachOf(c)
	if err != nil {
		return resourcereach.Reach{}, err
	}
	return reach.Selecting(source, scope), nil
}
