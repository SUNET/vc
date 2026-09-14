package apiv1

import (
	"context"
	"strings"

	"github.com/SUNET/vc/pkg/model"
)

// DashboardReply is the view model rendered by GET /dashboard.
type DashboardReply struct {
	Title    string
	Services []DashboardServiceView
}

// DashboardServiceView is a single service card on the dashboard.
type DashboardServiceView struct {
	Name        string
	URL         string
	Description string
	Links       []model.DashboardLink
	// Health is "healthy", "unhealthy" or "unknown".
	Health string
	// Message carries the first failing probe message when Health=="unhealthy".
	Message string
}

// Dashboard builds the /dashboard view model from cfg.APIGW.Dashboard.Services
// (seeded from sibling sections at config load, plus operator overrides) and
// joins per-service health from the cached status aggregator.
func (c *Client) Dashboard(ctx context.Context) (*DashboardReply, error) {
	ctx, span := c.tracer.Start(ctx, "apiv1:Dashboard")
	defer span.End()

	title := c.cfg.APIGW.Dashboard.Title
	if title == "" {
		title = "VC System Dashboard"
	}

	entries := c.cfg.APIGW.Dashboard.Services
	services := make([]DashboardServiceView, 0, len(entries))
	for _, s := range entries {
		services = append(services, DashboardServiceView{
			Name:        s.Name,
			URL:         s.URL,
			Description: s.Description,
			Links:       s.Links,
		})
	}

	c.applyHealth(ctx, services)

	return &DashboardReply{Title: title, Services: services}, nil
}

// applyHealth joins per-service health from the cached aggregator onto the
// service views. Probes are prefixed "<service>." by the aggregator; a service
// is healthy iff every one of its probes is healthy. Services with no probes
// (e.g. verifier, which apigw does not aggregate) are marked "unknown".
func (c *Client) applyHealth(ctx context.Context, services []DashboardServiceView) {
	if c.statusAggregator == nil {
		for i := range services {
			services[i].Health = "unknown"
		}
		return
	}
	reply := c.statusAggregator.Reply(ctx)
	probes := reply.GetData().GetProbes()

	for i := range services {
		prefix := services[i].Name + "."
		healthy := true
		var msg string
		seen := false
		for _, p := range probes {
			if !strings.HasPrefix(p.GetName(), prefix) {
				continue
			}
			seen = true
			if !p.GetHealthy() {
				healthy = false
				if msg == "" {
					msg = p.GetName() + ": " + p.GetMessage()
				}
			}
		}
		switch {
		case !seen:
			services[i].Health = "unknown"
		case healthy:
			services[i].Health = "healthy"
		default:
			services[i].Health = "unhealthy"
			services[i].Message = msg
		}
	}
}
