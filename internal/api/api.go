package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"nhooyr.io/websocket"

	"flowproxy/internal/backup"
	"flowproxy/internal/certmgr"
	"flowproxy/internal/clustersync"
	"flowproxy/internal/iprules"
	"flowproxy/internal/node"
	"flowproxy/internal/proxy"
	"flowproxy/internal/settings"
	"flowproxy/internal/site"
	"flowproxy/internal/store"
)

type Server struct {
	store              *store.Store
	router             *proxy.Router
	certMgr            *certmgr.Manager
	settingsStore      *settings.Store
	backupMgr          *backup.Manager
	nodeStore          *node.Store
	localNodeID        string
	readOnlyControl    bool
	readOnlyControlFn  func() bool
	readOnlyErrorFn    func() map[string]string
	onSitesChanged     func([]site.Site)
	onSettingsChanged  func(settings.Settings) error
	onClusterSyncInfo  func() clustersync.RuntimeStatus
	onControlPlaneInfo func() map[string]any
}

func New(st *store.Store, rt *proxy.Router, cm *certmgr.Manager, settingsStore *settings.Store, backupMgr *backup.Manager, nodeStore *node.Store, localNodeID string, readOnlyControl bool, onSitesChanged func([]site.Site), onSettingsChanged func(settings.Settings) error, onClusterSyncInfo func() clustersync.RuntimeStatus) *Server {
	return &Server{
		store:              st,
		router:             rt,
		certMgr:            cm,
		settingsStore:      settingsStore,
		backupMgr:          backupMgr,
		nodeStore:          nodeStore,
		localNodeID:        node.NormalizeID(localNodeID),
		readOnlyControl:    readOnlyControl,
		readOnlyControlFn:  nil,
		readOnlyErrorFn:    nil,
		onSitesChanged:     onSitesChanged,
		onSettingsChanged:  onSettingsChanged,
		onClusterSyncInfo:  onClusterSyncInfo,
		onControlPlaneInfo: nil,
	}
}

func (s *Server) SetReadOnlyControlFunc(fn func() bool) {
	s.readOnlyControlFn = fn
}

func (s *Server) SetReadOnlyControlErrorFunc(fn func() map[string]string) {
	s.readOnlyErrorFn = fn
}

func (s *Server) SetControlPlaneInfoFunc(fn func() map[string]any) {
	s.onControlPlaneInfo = fn
}

func (s *Server) isReadOnlyControl() bool {
	if s == nil {
		return true
	}
	if s.readOnlyControlFn != nil {
		return s.readOnlyControlFn()
	}
	return s.readOnlyControl
}

func (s *Server) writeReadOnlyControlError(w http.ResponseWriter) {
	if s.readOnlyErrorFn == nil {
		writeError(w, http.StatusForbidden, "control plane is read-only on this node")
		return
	}
	detail := s.readOnlyErrorFn()
	message := strings.TrimSpace(detail["message"])
	if message == "" {
		message = "control plane is read-only on this node"
	}
	payload := map[string]any{
		"error": message,
	}
	if leader := strings.TrimSpace(detail["leaderNodeId"]); leader != "" {
		payload["leaderNodeId"] = leader
	}
	if mode := strings.TrimSpace(detail["electionMode"]); mode != "" {
		payload["electionMode"] = mode
	}
	writeJSON(w, http.StatusForbidden, payload)
}

func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/logs", s.handleLogs)
	mux.HandleFunc("/api/logs/stream", s.handleLogStream)
	mux.HandleFunc("/api/sites", s.handleSites)
	mux.HandleFunc("/api/sites/", s.handleSiteByID)
	mux.HandleFunc("/api/certificates", s.handleCertificates)
	mux.HandleFunc("/api/certificates/", s.handleCertificateByID)
	mux.HandleFunc("/api/backups", s.handleBackups)
	mux.HandleFunc("/api/backups/download", s.handleBackupQuickDownload)
	mux.HandleFunc("/api/backups/upload", s.handleBackupUpload)
	mux.HandleFunc("/api/backups/", s.handleBackupByID)
	mux.HandleFunc("/api/settings", s.handleSettings)
	mux.HandleFunc("/api/cluster-sync", s.handleClusterSync)
	mux.HandleFunc("/api/nodes", s.handleNodes)
	mux.HandleFunc("/api/nodes/", s.handleNodeByID)
	mux.HandleFunc("/api/interfaces", s.handleInterfaces)
}

func (s *Server) handleInterfaces(w http.ResponseWriter, _ *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"interfaces": []map[string]any{}})
		return
	}
	type ifaceInfo struct {
		Name  string   `json:"name"`
		Addrs []string `json:"addrs"`
	}
	result := make([]ifaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		addrList := make([]string, 0)
		for _, addr := range addrs {
			addrList = append(addrList, addr.String())
		}
		if iface.Flags&net.FlagUp == 0 {
			continue // skip down interfaces
		}
		result = append(result, ifaceInfo{
			Name:  iface.Name,
			Addrs: addrList,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"interfaces": result})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleSites(w http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case http.MethodGet:
		if s.store != nil {
			_ = s.store.Reload()
		}
		writeJSON(w, http.StatusOK, sanitizeSites(s.store.List()))
	case http.MethodPost:
		if s.isReadOnlyControl() {
			s.writeReadOnlyControlError(w)
			return
		}
		beforeSites := s.store.List()
		var input site.Site
		if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		input.ID = newID()
		if err := prepareBasicAuth(&input, site.BasicAuthConfig{}); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.validateSelectedCertificate(input.CertificateID); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.validateNodeAssignment(input.NodeID); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		validationSite, err := s.resolveSiteForValidation(input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := site.Validate(validationSite); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		out, err := s.store.Create(input)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.reloadRouterAndNotify(); err != nil {
			msg := fmt.Sprintf("router reload failed: %v", err)
			if rbErr := s.rollbackSites(beforeSites); rbErr != nil {
				msg = fmt.Sprintf("%s; rollback failed: %v", msg, rbErr)
			}
			writeError(w, http.StatusInternalServerError, msg)
			return
		}
		writeJSON(w, http.StatusCreated, sanitizeSite(out))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSiteByID(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, "/api/sites/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "site ID is required")
		return
	}

	if strings.HasSuffix(id, "/toggle") {
		id = strings.TrimSuffix(id, "/toggle")
		s.handleToggle(w, req, id)
		return
	}
	if strings.HasSuffix(id, "/cache/purge") {
		id = strings.TrimSuffix(id, "/cache/purge")
		s.handlePurgeCache(w, req, id)
		return
	}

	switch req.Method {
	case http.MethodPut:
		if s.isReadOnlyControl() {
			s.writeReadOnlyControlError(w)
			return
		}
		beforeSites := s.store.List()
		current, err := s.store.Get(id)
		if err != nil {
			if err == store.ErrNotFound {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		payload, err := io.ReadAll(req.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		var input site.Site
		if err := json.Unmarshal(payload, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(payload, &raw)
		mergeOptionalSiteFieldsFromCurrent(raw, &input, current)
		if err := prepareBasicAuth(&input, current.BasicAuth); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.validateSelectedCertificate(input.CertificateID); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := s.validateNodeAssignment(input.NodeID); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		validationSite, err := s.resolveSiteForValidation(input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := site.Validate(validationSite); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		out, err := s.store.Update(id, input)
		if err != nil {
			if err == store.ErrNotFound {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.reloadRouterAndNotify(); err != nil {
			msg := fmt.Sprintf("router reload failed: %v", err)
			if rbErr := s.rollbackSites(beforeSites); rbErr != nil {
				msg = fmt.Sprintf("%s; rollback failed: %v", msg, rbErr)
			}
			writeError(w, http.StatusInternalServerError, msg)
			return
		}
		writeJSON(w, http.StatusOK, sanitizeSite(out))
	case http.MethodDelete:
		if s.isReadOnlyControl() {
			s.writeReadOnlyControlError(w)
			return
		}
		beforeSites := s.store.List()
		if err := s.store.Delete(id); err != nil {
			if err == store.ErrNotFound {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if err := s.reloadRouterAndNotify(); err != nil {
			msg := fmt.Sprintf("router reload failed: %v", err)
			if rbErr := s.rollbackSites(beforeSites); rbErr != nil {
				msg = fmt.Sprintf("%s; rollback failed: %v", msg, rbErr)
			}
			writeError(w, http.StatusInternalServerError, msg)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePurgeCache(w http.ResponseWriter, req *http.Request, id string) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.isReadOnlyControl() {
		s.writeReadOnlyControlError(w)
		return
	}
	purged, ok := s.router.PurgeSiteCache(id)
	if !ok {
		writeError(w, http.StatusNotFound, "site not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"siteId":        id,
		"purgedEntries": purged,
	})
}

func (s *Server) handleToggle(w http.ResponseWriter, req *http.Request, id string) {
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.isReadOnlyControl() {
		s.writeReadOnlyControlError(w)
		return
	}
	type toggleInput struct {
		Enabled bool `json:"enabled"`
	}
	var input toggleInput
	if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	beforeSites := s.store.List()
	out, err := s.store.SetEnabled(id, input.Enabled)
	if err != nil {
		if err == store.ErrNotFound {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.reloadRouterAndNotify(); err != nil {
		msg := fmt.Sprintf("router reload failed: %v", err)
		if rbErr := s.rollbackSites(beforeSites); rbErr != nil {
			msg = fmt.Sprintf("%s; rollback failed: %v", msg, rbErr)
		}
		writeError(w, http.StatusInternalServerError, msg)
		return
	}
	writeJSON(w, http.StatusOK, sanitizeSite(out))
}

func (s *Server) handleStats(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.nodeStore != nil {
		_ = s.nodeStore.Reload()
	}
	snapshot := s.router.Stats()
	if s.nodeStore != nil {
		cluster := s.buildClusterSnapshot()
		writeJSON(w, http.StatusOK, map[string]any{
			"timestamp":        snapshot.Timestamp,
			"totalSites":       snapshot.TotalSites,
			"enabledSites":     snapshot.EnabledSites,
			"totalRequests":    snapshot.TotalRequests,
			"successRequests":  snapshot.SuccessRequests,
			"failedRequests":   snapshot.FailedRequests,
			"averageLatencyMs": snapshot.AverageLatencyMs,
			"successRate":      snapshot.SuccessRate,
			"topSites":         snapshot.TopSites,
			"cluster":          cluster,
		})
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleLogs(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	query := req.URL.Query()
	limit, err := parsePositiveInt(query.Get("limit"), 100, 5000, "limit")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	statusMin, err := parsePositiveInt(query.Get("statusMin"), 0, 999, "statusMin")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	statusMax, err := parsePositiveInt(query.Get("statusMax"), 0, 999, "statusMax")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if statusMin > 0 && statusMax > 0 && statusMin > statusMax {
		writeError(w, http.StatusBadRequest, "statusMin must be <= statusMax")
		return
	}

	rawSince := strings.TrimSpace(query.Get("since"))
	rawFrom := strings.TrimSpace(query.Get("from"))
	rawTo := strings.TrimSpace(query.Get("to"))
	if rawSince != "" && rawFrom != "" {
		writeError(w, http.StatusBadRequest, "from and since cannot be used together")
		return
	}

	var from *time.Time
	var to *time.Time
	if rawSince != "" {
		d, err := time.ParseDuration(rawSince)
		if err != nil || d <= 0 {
			writeError(w, http.StatusBadRequest, "since must be a positive duration")
			return
		}
		t := time.Now().UTC().Add(-d)
		from = &t
	}
	if rawFrom != "" {
		t, err := parseLogTime(rawFrom, false)
		if err != nil {
			writeError(w, http.StatusBadRequest, "from must be RFC3339 time, date(YYYY-MM-DD), or unix seconds")
			return
		}
		u := t.UTC()
		from = &u
	}
	if rawTo != "" {
		t, err := parseLogTime(rawTo, true)
		if err != nil {
			writeError(w, http.StatusBadRequest, "to must be RFC3339 time, date(YYYY-MM-DD), or unix seconds")
			return
		}
		u := t.UTC()
		to = &u
	}
	if from != nil && to != nil && from.After(*to) {
		writeError(w, http.StatusBadRequest, "from must be <= to")
		return
	}

	writeJSON(w, http.StatusOK, s.router.QueryLogs(proxy.AccessLogQuery{
		Limit:     limit,
		From:      from,
		To:        to,
		SiteID:    strings.TrimSpace(query.Get("siteId")),
		Domain:    strings.TrimSpace(query.Get("domain")),
		StatusMin: statusMin,
		StatusMax: statusMax,
	}))
}

func (s *Server) handleLogStream(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	conn, err := websocket.Accept(w, req, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusInternalError, "connection closed")

	ctx := req.Context()
	ch := make(chan proxy.AccessLogEntry, 64)
	subID := s.router.SubscribeLogs(ch)
	defer s.router.UnsubscribeLogs(subID)

	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		_ = conn.Close(websocket.StatusNormalClosure, "client disconnected")
	}()

	for {
		select {
		case <-done:
			return
		case entry, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			err = conn.Write(ctx, websocket.MessageText, data)
			if err != nil {
				return
			}
		}
	}
}

func (s *Server) handleCertificates(w http.ResponseWriter, req *http.Request) {
	if s.certMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "certificate manager is not available")
		return
	}
	switch req.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.certMgr.List())
	case http.MethodPost:
		if s.isReadOnlyControl() {
			s.writeReadOnlyControlError(w)
			return
		}
		var input certmgr.Certificate
		if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		input.ID = newID()
		out, err := s.certMgr.Create(input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCertificateByID(w http.ResponseWriter, req *http.Request) {
	if s.certMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "certificate manager is not available")
		return
	}
	id := strings.TrimPrefix(req.URL.Path, "/api/certificates/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "certificate ID is required")
		return
	}
	if strings.HasSuffix(id, "/issue") {
		id = strings.TrimSuffix(id, "/issue")
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if s.isReadOnlyControl() {
			s.writeReadOnlyControlError(w)
			return
		}
		item, err := s.certMgr.Issue(id)
		if err != nil {
			if err == certmgr.ErrNotFound {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, item)
		return
	}
	if strings.HasSuffix(id, "/download") {
		id = strings.TrimSuffix(id, "/download")
		s.handleCertificateDownload(w, req, id)
		return
	}
	switch req.Method {
	case http.MethodDelete:
		if s.isReadOnlyControl() {
			s.writeReadOnlyControlError(w)
			return
		}
		if s.isCertificateInUse(id) {
			writeError(w, http.StatusBadRequest, "certificate is in use by a site")
			return
		}
		if err := s.certMgr.Delete(id); err != nil {
			if err == certmgr.ErrNotFound {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCertificateDownload(w http.ResponseWriter, req *http.Request, id string) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	query := req.URL.Query()
	asset := strings.TrimSpace(strings.ToLower(query.Get("asset")))
	if asset == "" {
		asset = strings.TrimSpace(strings.ToLower(query.Get("kind")))
	}
	format := strings.TrimSpace(strings.ToLower(query.Get("format")))
	password := query.Get("password")
	data, filename, contentType, err := s.certMgr.DownloadMaterial(id, asset, format, password)
	if err != nil {
		if err == certmgr.ErrNotFound {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if err == certmgr.ErrMaterialUnavailable {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleSettings(w http.ResponseWriter, req *http.Request) {
	if s.settingsStore == nil {
		writeError(w, http.StatusServiceUnavailable, "settings store is not available")
		return
	}

	switch req.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.settingsStore.Get())
	case http.MethodPut:
		if s.isReadOnlyControl() {
			s.writeReadOnlyControlError(w)
			return
		}
		current := s.settingsStore.Get()
		payload, err := io.ReadAll(req.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		payload = sanitizeSettingsPayload(payload)
		var input settings.Settings
		if err := json.Unmarshal(payload, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(payload, &raw)
		// Keep existing values when clients submit partial payloads.
		if strings.TrimSpace(input.Language) == "" {
			input.Language = current.Language
		}
		if input.WebPort == 0 {
			input.WebPort = current.WebPort
		}
		if input.WebAccess.AllowCIDRs == nil {
			input.WebAccess.AllowCIDRs = current.WebAccess.AllowCIDRs
		}
		if input.WebAccess.DenyCIDRs == nil {
			input.WebAccess.DenyCIDRs = current.WebAccess.DenyCIDRs
		}
		if _, ok := raw["ipRuleSourceOrder"]; !ok && input.IPRuleSourceOrder == nil {
			input.IPRuleSourceOrder = current.IPRuleSourceOrder
		}
		if input.IPRuleSets == nil {
			input.IPRuleSets = current.IPRuleSets
		}
		if input.IPCountryAutoUpdates == nil {
			input.IPCountryAutoUpdates = current.IPCountryAutoUpdates
		}
		rawBackup := map[string]json.RawMessage{}
		if item, ok := raw["backup"]; ok {
			_ = json.Unmarshal(item, &rawBackup)
		}
		rawAlert := map[string]json.RawMessage{}
		if item, ok := raw["alert"]; ok {
			_ = json.Unmarshal(item, &rawAlert)
		}
		rawAdminTLS := map[string]json.RawMessage{}
		if item, ok := raw["adminTls"]; ok {
			_ = json.Unmarshal(item, &rawAdminTLS)
		}
		rawClusterSync := map[string]json.RawMessage{}
		if item, ok := raw["clusterSync"]; ok {
			_ = json.Unmarshal(item, &rawClusterSync)
		}
		if _, ok := raw["backup"]; !ok {
			input.Backup = current.Backup
		} else {
			if _, ok := rawBackup["enabled"]; !ok {
				input.Backup.Enabled = current.Backup.Enabled
			}
			if _, ok := rawBackup["interval"]; !ok && strings.TrimSpace(input.Backup.Interval) == "" {
				input.Backup.Interval = current.Backup.Interval
			}
			if _, ok := rawBackup["keepLast"]; !ok && input.Backup.KeepLast == 0 {
				input.Backup.KeepLast = current.Backup.KeepLast
			}
		}
		if _, ok := raw["alert"]; !ok {
			input.Alert = current.Alert
		} else {
			if _, ok := rawAlert["webhookUrl"]; !ok {
				input.Alert.WebhookURL = current.Alert.WebhookURL
			}
			if _, ok := rawAlert["consecutive5xx"]; !ok && input.Alert.Consecutive5xx == 0 {
				input.Alert.Consecutive5xx = current.Alert.Consecutive5xx
			}
			if _, ok := rawAlert["latencyMs"]; !ok {
				input.Alert.LatencyMs = current.Alert.LatencyMs
			}
			if _, ok := rawAlert["cooldown"]; !ok && strings.TrimSpace(input.Alert.Cooldown) == "" {
				input.Alert.Cooldown = current.Alert.Cooldown
			}
		}
		if _, ok := raw["adminTls"]; !ok {
			input.AdminTLS = current.AdminTLS
		} else {
			if _, ok := rawAdminTLS["enabled"]; !ok {
				input.AdminTLS.Enabled = current.AdminTLS.Enabled
			}
			if _, ok := rawAdminTLS["httpsPort"]; !ok && input.AdminTLS.HTTPSPort == 0 {
				input.AdminTLS.HTTPSPort = current.AdminTLS.HTTPSPort
			}
			if _, ok := rawAdminTLS["redirectHttp"]; !ok {
				input.AdminTLS.RedirectHTTP = current.AdminTLS.RedirectHTTP
			}
			if _, ok := rawAdminTLS["autoSelfSigned"]; !ok {
				input.AdminTLS.AutoSelfSigned = current.AdminTLS.AutoSelfSigned
			}
			if _, ok := rawAdminTLS["certificateId"]; !ok && strings.TrimSpace(input.AdminTLS.CertificateID) == "" {
				input.AdminTLS.CertificateID = current.AdminTLS.CertificateID
			}
			if _, ok := rawAdminTLS["certFile"]; !ok && strings.TrimSpace(input.AdminTLS.CertFile) == "" {
				input.AdminTLS.CertFile = current.AdminTLS.CertFile
			}
			if _, ok := rawAdminTLS["keyFile"]; !ok && strings.TrimSpace(input.AdminTLS.KeyFile) == "" {
				input.AdminTLS.KeyFile = current.AdminTLS.KeyFile
			}
		}
		if _, ok := raw["ipCountryAutoUpdates"]; ok {
			input.IPCountryAutoUpdates = mergeIPCountryAutoUpdateRuntimeFields(current.IPCountryAutoUpdates, input.IPCountryAutoUpdates)
		}
		if _, ok := raw["clusterSync"]; !ok {
			input.ClusterSync = current.ClusterSync
		} else {
			if _, ok := rawClusterSync["certificateSyncEnabled"]; !ok {
				input.ClusterSync.CertificateSyncEnabled = current.ClusterSync.CertificateSyncEnabled
			}
			if _, ok := rawClusterSync["failCloseEnabled"]; !ok {
				input.ClusterSync.FailCloseEnabled = current.ClusterSync.FailCloseEnabled
			}
			if _, ok := rawClusterSync["failCloseConsecutiveFailures"]; !ok && input.ClusterSync.FailCloseConsecutiveFailures == 0 {
				input.ClusterSync.FailCloseConsecutiveFailures = current.ClusterSync.FailCloseConsecutiveFailures
			}
			if _, ok := rawClusterSync["failCloseStaleAfter"]; !ok && strings.TrimSpace(input.ClusterSync.FailCloseStaleAfter) == "" {
				input.ClusterSync.FailCloseStaleAfter = current.ClusterSync.FailCloseStaleAfter
			}
		}
		if s.store != nil {
			if _, err := iprules.ResolveSitesForRuntime(s.store.List(), input); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		out, err := s.settingsStore.Update(input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if s.onSettingsChanged != nil {
			if err := s.onSettingsChanged(out); err != nil {
				if _, rbErr := s.settingsStore.Update(current); rbErr != nil {
					writeError(w, http.StatusInternalServerError, fmt.Sprintf("apply settings failed: %v; rollback failed: %v", err, rbErr))
					return
				}
				writeError(w, http.StatusInternalServerError, fmt.Sprintf("apply settings failed: %v", err))
				return
			}
		}
		writeJSON(w, http.StatusOK, out)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleClusterSync(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.onClusterSyncInfo == nil {
		writeJSON(w, http.StatusOK, clustersync.RuntimeStatus{
			Mode: clustersync.ModeController,
		})
		return
	}
	writeJSON(w, http.StatusOK, s.onClusterSyncInfo())
}

func sanitizeSettingsPayload(payload []byte) []byte {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return payload
	}
	itemsRaw, ok := raw["ipCountryAutoUpdates"]
	if !ok {
		return payload
	}
	items, ok := itemsRaw.([]any)
	if !ok {
		return payload
	}
	changed := false
	for _, itemRaw := range items {
		item, ok := itemRaw.(map[string]any)
		if !ok {
			continue
		}
		for _, key := range []string{"cidrs", "lastAttemptAt", "lastSyncAt", "lastError"} {
			if _, exists := item[key]; exists {
				delete(item, key)
				changed = true
			}
		}
	}
	if !changed {
		return payload
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return payload
	}
	return out
}

func (s *Server) handleBackups(w http.ResponseWriter, req *http.Request) {
	if s.backupMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "backup manager is not available")
		return
	}
	switch req.Method {
	case http.MethodGet:
		items, err := s.backupMgr.List(200)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items":   items,
			"status":  s.backupMgr.Status(),
			"count":   len(items),
			"updated": time.Now().UTC(),
		})
	case http.MethodPost:
		item, err := s.backupMgr.Create("manual")
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, item)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleBackupByID(w http.ResponseWriter, req *http.Request) {
	if s.backupMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "backup manager is not available")
		return
	}
	id := strings.TrimPrefix(req.URL.Path, "/api/backups/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "backup name is required")
		return
	}
	if !strings.HasSuffix(id, "/download") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	id = strings.TrimSuffix(id, "/download")
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	path, item, err := s.backupMgr.Resolve(id)
	if err != nil {
		if err == backup.ErrNotFound {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", item.Name))
	http.ServeFile(w, req, path)
}

func (s *Server) handleBackupQuickDownload(w http.ResponseWriter, req *http.Request) {
	if s.backupMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "backup manager is not available")
		return
	}
	if req.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	item, err := s.backupMgr.Create("manual-download")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	path, resolved, err := s.backupMgr.Resolve(item.Name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", resolved.Name))
	http.ServeFile(w, req, path)
}

func (s *Server) handleBackupUpload(w http.ResponseWriter, req *http.Request) {
	if s.backupMgr == nil {
		writeError(w, http.StatusServiceUnavailable, "backup manager is not available")
		return
	}
	if req.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	const maxUploadSize = 512 << 20 // 512MB
	req.Body = http.MaxBytesReader(w, req.Body, maxUploadSize)
	if err := req.ParseMultipartForm(maxUploadSize); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form")
		return
	}
	file, header, err := req.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	item, err := s.backupMgr.Import(file, header.Filename)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func parsePositiveInt(raw string, fallback int, max int, field string) (int, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s must be a non-negative integer", field)
	}
	if n == 0 {
		if field == "limit" {
			return 0, fmt.Errorf("limit must be a positive integer")
		}
		return 0, nil
	}
	if max > 0 && n > max {
		n = max
	}
	return n, nil
}

func parseLogTime(raw string, endOfDay bool) (time.Time, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, fmt.Errorf("empty time")
	}
	if unix, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(unix, 0).UTC(), nil
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02",
	}
	for _, layout := range layouts {
		t, err := time.Parse(layout, value)
		if err == nil {
			if layout == "2006-01-02" {
				base := t.UTC()
				if endOfDay {
					return base.Add(23*time.Hour + 59*time.Minute + 59*time.Second), nil
				}
				return base, nil
			}
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time")
}

func mergeIPCountryAutoUpdateRuntimeFields(current []settings.IPCountryAutoUpdate, next []settings.IPCountryAutoUpdate) []settings.IPCountryAutoUpdate {
	if len(next) == 0 {
		return next
	}
	currentByID := map[string]settings.IPCountryAutoUpdate{}
	for _, item := range current {
		key := strings.ToLower(strings.TrimSpace(item.ID))
		if key == "" {
			continue
		}
		currentByID[key] = item
	}
	out := make([]settings.IPCountryAutoUpdate, 0, len(next))
	for _, item := range next {
		key := strings.ToLower(strings.TrimSpace(item.ID))
		matched, ok := currentByID[key]
		if ok {
			item.CIDRs = append([]string{}, matched.CIDRs...)
			item.LastAttemptAt = matched.LastAttemptAt
			item.LastSyncAt = matched.LastSyncAt
			item.LastError = matched.LastError
		}
		out = append(out, item)
	}
	return out
}

func prepareBasicAuth(input *site.Site, previous site.BasicAuthConfig) error {
	input.BasicAuth.Username = strings.TrimSpace(input.BasicAuth.Username)
	input.BasicAuth.Password = strings.TrimSpace(input.BasicAuth.Password)
	input.BasicAuth.PasswordHash = strings.TrimSpace(input.BasicAuth.PasswordHash)

	if !input.BasicAuth.Enabled {
		input.BasicAuth.Username = ""
		input.BasicAuth.Password = ""
		input.BasicAuth.PasswordHash = ""
		return nil
	}

	if input.BasicAuth.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(input.BasicAuth.Password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash basic auth password: %w", err)
		}
		input.BasicAuth.PasswordHash = string(hash)
	}
	if input.BasicAuth.PasswordHash == "" {
		input.BasicAuth.PasswordHash = previous.PasswordHash
	}
	input.BasicAuth.Password = ""
	return nil
}

func mergeOptionalSiteFieldsFromCurrent(raw map[string]json.RawMessage, input *site.Site, current site.Site) {
	if _, ok := raw["name"]; !ok {
		input.Name = current.Name
	}
	if _, ok := raw["nodeId"]; !ok {
		input.NodeID = current.NodeID
	}
	if _, ok := raw["domain"]; !ok {
		input.Domain = current.Domain
	}
	if _, ok := raw["listenPort"]; !ok {
		input.ListenPort = current.ListenPort
	}
	if _, ok := raw["additionalDomains"]; !ok {
		input.AdditionalDomains = append([]string{}, current.AdditionalDomains...)
	}
	if _, ok := raw["certificateId"]; !ok {
		input.CertificateID = current.CertificateID
	}
	if _, ok := raw["upstream"]; !ok {
		input.Upstream = current.Upstream
	}
	if _, ok := raw["upstreams"]; !ok {
		input.Upstreams = append([]site.Upstream{}, current.Upstreams...)
	}
	if _, ok := raw["loadBalanceStrategy"]; !ok {
		input.LoadBalanceStrategy = current.LoadBalanceStrategy
	}
	if _, ok := raw["routes"]; !ok {
		input.Routes = append([]site.RouteRule{}, current.Routes...)
	}
	if _, ok := raw["trafficControl"]; !ok {
		input.TrafficControl = current.TrafficControl
	}
	if _, ok := raw["security"]; !ok {
		input.Security = current.Security
	}
	if _, ok := raw["resilience"]; !ok {
		input.Resilience = current.Resilience
	}
	if _, ok := raw["cache"]; !ok {
		input.Cache = current.Cache
	}
	if _, ok := raw["gzip"]; !ok {
		input.Gzip = current.Gzip
	}
	if _, ok := raw["brotli"]; !ok {
		input.Brotli = current.Brotli
	}
	if _, ok := raw["canary"]; !ok {
		input.Canary = current.Canary
	}
	if _, ok := raw["upstreamTls"]; !ok {
		input.UpstreamTLS = current.UpstreamTLS
	}
	if _, ok := raw["timeouts"]; !ok {
		input.Timeouts = current.Timeouts
	}
	if _, ok := raw["autoRequestHeaders"]; !ok {
		input.AutoRequestHeaders = current.AutoRequestHeaders
	}
	if _, ok := raw["autoResponseHeaders"]; !ok {
		input.AutoResponseHeaders = current.AutoResponseHeaders
	}
	if _, ok := raw["requestHeaders"]; !ok {
		input.RequestHeaders = append([]site.Header{}, current.RequestHeaders...)
	}
	if _, ok := raw["responseHeaders"]; !ok {
		input.ResponseHeaders = append([]site.Header{}, current.ResponseHeaders...)
	}
	if _, ok := raw["removeRequestHeaders"]; !ok {
		input.RemoveRequestHeaders = append([]string{}, current.RemoveRequestHeaders...)
	}
	if _, ok := raw["removeResponseHeaders"]; !ok {
		input.RemoveResponseHeaders = append([]string{}, current.RemoveResponseHeaders...)
	}
	if _, ok := raw["rateLimit"]; !ok {
		input.RateLimit = current.RateLimit
	}
	if _, ok := raw["ipRuleSetId"]; !ok {
		input.IPRuleSetID = current.IPRuleSetID
	}
	if _, ok := raw["ipRuleSetIds"]; !ok {
		input.IPRuleSetIDs = append([]string{}, current.IPRuleSetIDs...)
	}
	if _, ok := raw["ipAccess"]; !ok {
		input.IPAccess = current.IPAccess
	}
	if _, ok := raw["basicAuth"]; !ok {
		input.BasicAuth = current.BasicAuth
	}
	if _, ok := raw["enabled"]; !ok {
		input.Enabled = current.Enabled
	}
	if _, ok := raw["forceHttps"]; !ok {
		input.ForceHTTPS = current.ForceHTTPS
	}
}

func sanitizeSites(items []site.Site) []site.Site {
	out := make([]site.Site, 0, len(items))
	for _, item := range items {
		out = append(out, sanitizeSite(item))
	}
	return out
}

func sanitizeSite(item site.Site) site.Site {
	item.BasicAuth.Password = ""
	item.BasicAuth.PasswordHash = ""
	return item
}

func (s *Server) handleNodes(w http.ResponseWriter, req *http.Request) {
	if s.nodeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "node store is not available")
		return
	}
	_ = s.nodeStore.Reload()
	switch req.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.buildRuntimeNodes())
	case http.MethodPost:
		if s.isReadOnlyControl() {
			s.writeReadOnlyControlError(w)
			return
		}
		var input node.Node
		if err := json.NewDecoder(req.Body).Decode(&input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		out, err := s.nodeStore.Upsert(input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, s.enrichRuntimeNode(out))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleNodeByID(w http.ResponseWriter, req *http.Request) {
	if s.nodeStore == nil {
		writeError(w, http.StatusServiceUnavailable, "node store is not available")
		return
	}
	id := strings.TrimPrefix(req.URL.Path, "/api/nodes/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "node ID is required")
		return
	}
	if strings.HasSuffix(id, "/heartbeat") {
		id = strings.TrimSuffix(id, "/heartbeat")
		if req.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		current, err := s.nodeStore.Get(id)
		if err != nil {
			if err == node.ErrNotFound {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		out, err := s.nodeStore.TouchHeartbeat(current.ID, current.Name, current.Endpoint, current.Tags, current.Enabled)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.enrichRuntimeNode(out))
		return
	}

	switch req.Method {
	case http.MethodPut:
		if s.isReadOnlyControl() {
			s.writeReadOnlyControlError(w)
			return
		}
		payload, err := io.ReadAll(req.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		var input node.Node
		if err := json.Unmarshal(payload, &input); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		var raw map[string]json.RawMessage
		_ = json.Unmarshal(payload, &raw)
		input.ID = id
		current, err := s.nodeStore.Get(id)
		if err != nil {
			if err == node.ErrNotFound {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if _, ok := raw["name"]; !ok && strings.TrimSpace(input.Name) == "" {
			input.Name = current.Name
		}
		if _, ok := raw["endpoint"]; !ok && strings.TrimSpace(input.Endpoint) == "" {
			input.Endpoint = current.Endpoint
		}
		if _, ok := raw["tags"]; !ok && input.Tags == nil {
			input.Tags = current.Tags
		}
		if _, ok := raw["enabled"]; !ok {
			input.Enabled = current.Enabled
		}
		if _, ok := raw["mode"]; !ok && strings.TrimSpace(input.Mode) == "" {
			input.Mode = current.Mode
		}
		input.CreatedAt = current.CreatedAt
		input.LastHeartbeatAt = current.LastHeartbeatAt
		out, err := s.nodeStore.Upsert(input)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, s.enrichRuntimeNode(out))
	case http.MethodDelete:
		if s.isReadOnlyControl() {
			s.writeReadOnlyControlError(w)
			return
		}
		if node.NormalizeID(id) == s.localNodeID {
			writeError(w, http.StatusBadRequest, "cannot delete the local node")
			return
		}
		for _, item := range s.store.List() {
			if node.NormalizeID(item.NodeID) == node.NormalizeID(id) {
				writeError(w, http.StatusBadRequest, "node still has assigned sites")
				return
			}
		}
		if err := s.nodeStore.Delete(id); err != nil {
			if err == node.ErrNotFound {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) validateSelectedCertificate(certificateID string) error {
	certificateID = strings.TrimSpace(certificateID)
	if certificateID == "" {
		return nil
	}
	if s.certMgr == nil {
		return fmt.Errorf("certificate manager is not available")
	}

	item, err := s.certMgr.Get(certificateID)
	if err != nil {
		if err == certmgr.ErrNotFound {
			return fmt.Errorf("certificate not found")
		}
		return err
	}
	if item.Type != certmgr.TypeSelfSigned {
		return fmt.Errorf("only active self-signed certificates can be selected")
	}
	if item.Status != certmgr.StatusActive {
		return fmt.Errorf("selected certificate is not active")
	}
	if strings.TrimSpace(item.Material.CertFile) == "" || strings.TrimSpace(item.Material.KeyFile) == "" {
		return fmt.Errorf("selected certificate has no usable key pair")
	}
	return nil
}

func (s *Server) validateNodeAssignment(nodeID string) error {
	if s.nodeStore == nil {
		return nil
	}
	key := node.NormalizeID(nodeID)
	if _, err := s.nodeStore.Get(key); err != nil {
		if err == node.ErrNotFound {
			return fmt.Errorf("node not found")
		}
		return err
	}
	return nil
}

func (s *Server) isCertificateInUse(certificateID string) bool {
	certificateID = strings.TrimSpace(certificateID)
	if certificateID == "" {
		return false
	}
	for _, item := range s.store.List() {
		if strings.TrimSpace(item.CertificateID) == certificateID {
			return true
		}
	}
	return false
}

func (s *Server) reloadRouterAndNotify() error {
	sites := s.store.List()
	runtimeSites, err := s.resolveSitesForRuntime(sites)
	if err != nil {
		return err
	}
	if err := s.router.Load(runtimeSites); err != nil {
		return err
	}
	if s.onSitesChanged != nil {
		s.onSitesChanged(sites)
	}
	return nil
}

func (s *Server) rollbackSites(previous []site.Site) error {
	if err := s.store.ReplaceAll(previous); err != nil {
		return err
	}
	runtimeSites, err := s.resolveSitesForRuntime(previous)
	if err != nil {
		return err
	}
	return s.router.Load(runtimeSites)
}

func (s *Server) resolveSiteForValidation(input site.Site) (site.Site, error) {
	if s.settingsStore == nil {
		return input, nil
	}
	return iprules.ResolveSiteIPAccess(input, s.settingsStore.Get())
}

func (s *Server) resolveSitesForRuntime(items []site.Site) ([]site.Site, error) {
	items = filterSitesByNodeID(items, s.localNodeID)
	if s.settingsStore == nil {
		return items, nil
	}
	return iprules.ResolveSitesForRuntime(items, s.settingsStore.Get())
}

func (s *Server) buildClusterSnapshot() map[string]any {
	nodes := s.buildRuntimeNodes()
	total := len(nodes)
	online := 0
	for _, item := range nodes {
		if item.Status == node.StatusOnline {
			online++
		}
	}
	out := map[string]any{
		"localNodeId": s.localNodeID,
		"totalNodes":  total,
		"onlineNodes": online,
		"nodes":       nodes,
	}
	if s.onControlPlaneInfo != nil {
		for k, v := range s.onControlPlaneInfo() {
			out[k] = v
		}
	}
	return out
}

func (s *Server) buildRuntimeNodes() []node.RuntimeNode {
	if s.nodeStore == nil {
		return nil
	}
	items := s.nodeStore.List()
	out := make([]node.RuntimeNode, 0, len(items))
	for _, item := range items {
		out = append(out, s.enrichRuntimeNode(item))
	}
	return out
}

func (s *Server) enrichRuntimeNode(item node.Node) node.RuntimeNode {
	runtime := node.RuntimeNode{
		Node:    item,
		Status:  node.RuntimeStatus(item, time.Now().UTC(), node.DefaultHeartbeatTTL),
		IsLocal: node.NormalizeID(item.ID) == s.localNodeID,
	}
	if s.store == nil {
		return runtime
	}
	for _, siteItem := range s.store.List() {
		if node.NormalizeID(siteItem.NodeID) != node.NormalizeID(item.ID) {
			continue
		}
		runtime.AssignedSites++
		if siteItem.Enabled {
			runtime.AssignedEnabled++
		}
	}
	return runtime
}

func filterSitesByNodeID(items []site.Site, nodeID string) []site.Site {
	target := node.NormalizeID(nodeID)
	out := make([]site.Site, 0, len(items))
	for _, item := range items {
		if node.NormalizeID(item.NodeID) != target {
			continue
		}
		out = append(out, item)
	}
	return out
}
