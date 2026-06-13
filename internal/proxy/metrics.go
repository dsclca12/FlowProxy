package proxy

import (
	"fmt"
	"strings"
)

func (r *Router) PrometheusMetrics() string {
	snapshot := r.Stats()
	builder := strings.Builder{}
	builder.WriteString("# HELP flowproxy_sites_total Total configured sites\n")
	builder.WriteString("# TYPE flowproxy_sites_total gauge\n")
	builder.WriteString(fmt.Sprintf("flowproxy_sites_total %d\n", snapshot.TotalSites))
	builder.WriteString("# HELP flowproxy_sites_enabled Enabled sites\n")
	builder.WriteString("# TYPE flowproxy_sites_enabled gauge\n")
	builder.WriteString(fmt.Sprintf("flowproxy_sites_enabled %d\n", snapshot.EnabledSites))
	builder.WriteString("# HELP flowproxy_requests_total Total proxied requests\n")
	builder.WriteString("# TYPE flowproxy_requests_total counter\n")
	builder.WriteString(fmt.Sprintf("flowproxy_requests_total %d\n", snapshot.TotalRequests))
	builder.WriteString("# HELP flowproxy_requests_success_total Successful proxied requests\n")
	builder.WriteString("# TYPE flowproxy_requests_success_total counter\n")
	builder.WriteString(fmt.Sprintf("flowproxy_requests_success_total %d\n", snapshot.SuccessRequests))
	builder.WriteString("# HELP flowproxy_requests_failed_total Failed proxied requests\n")
	builder.WriteString("# TYPE flowproxy_requests_failed_total counter\n")
	builder.WriteString(fmt.Sprintf("flowproxy_requests_failed_total %d\n", snapshot.FailedRequests))
	builder.WriteString("# HELP flowproxy_request_latency_avg_ms Average request latency in milliseconds\n")
	builder.WriteString("# TYPE flowproxy_request_latency_avg_ms gauge\n")
	builder.WriteString(fmt.Sprintf("flowproxy_request_latency_avg_ms %.2f\n", snapshot.AverageLatencyMs))

	builder.WriteString("# HELP flowproxy_site_requests_total Requests by site\n")
	builder.WriteString("# TYPE flowproxy_site_requests_total counter\n")
	builder.WriteString("# HELP flowproxy_site_requests_failed_total Failed requests by site\n")
	builder.WriteString("# TYPE flowproxy_site_requests_failed_total counter\n")
	builder.WriteString("# HELP flowproxy_site_request_latency_avg_ms Average request latency by site\n")
	builder.WriteString("# TYPE flowproxy_site_request_latency_avg_ms gauge\n")
	for _, item := range snapshot.TopSites {
		siteID := escapePrometheusLabel(item.SiteID)
		domain := escapePrometheusLabel(item.Domain)
		builder.WriteString(fmt.Sprintf("flowproxy_site_requests_total{site_id=\"%s\",domain=\"%s\"} %d\n", siteID, domain, item.Requests))
		builder.WriteString(fmt.Sprintf("flowproxy_site_requests_failed_total{site_id=\"%s\",domain=\"%s\"} %d\n", siteID, domain, item.FailedRequests))
		builder.WriteString(fmt.Sprintf("flowproxy_site_request_latency_avg_ms{site_id=\"%s\",domain=\"%s\"} %.2f\n", siteID, domain, item.AverageLatencyMs))
	}
	return builder.String()
}

func escapePrometheusLabel(value string) string {
	value = strings.ReplaceAll(value, `\\`, `\\\\`)
	value = strings.ReplaceAll(value, `"`, `\\"`)
	value = strings.ReplaceAll(value, "\n", `\\n`)
	return value
}
