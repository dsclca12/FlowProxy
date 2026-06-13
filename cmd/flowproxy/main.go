package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"flowproxy/internal/adminauth"
	"flowproxy/internal/api"
	"flowproxy/internal/backup"
	"flowproxy/internal/certmgr"
	"flowproxy/internal/clustersync"
	"flowproxy/internal/config"
	"flowproxy/internal/ipcountry"
	"flowproxy/internal/iprules"
	"flowproxy/internal/node"
	"flowproxy/internal/persist"
	"flowproxy/internal/proxy"
	"flowproxy/internal/settings"
	"flowproxy/internal/site"
	"flowproxy/internal/store"
	"flowproxy/internal/ui"
)

func main() {
	handled, err := tryHandleAdminCLI(os.Args[1:])
	if handled {
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	cfg := config.Load()
	fileCfg, err := config.LoadFromFile(cfg.ConfigFile)
	if err != nil {
		log.Fatalf("failed to load config file: %v", err)
	}
	if fileCfg != nil {
		if err := cfg.ApplyRuntimeFile(fileCfg.Runtime); err != nil {
			log.Fatalf("failed to apply runtime config: %v", err)
		}
		if cfg.StorageBackend != "etcd" {
			if err := config.ApplyDataFileConfig(cfg, fileCfg); err != nil {
				log.Fatalf("failed to apply file data config: %v", err)
			}
		}
		log.Printf("loaded declarative config from %s", cfg.ConfigFile)
	}
	cfg.NodeID = node.NormalizeID(cfg.NodeID)
	cfg.NodeName = node.NormalizeName(cfg.NodeName)
	cfg.StorageBackend = strings.ToLower(strings.TrimSpace(cfg.StorageBackend))
	if cfg.StorageBackend == "" {
		cfg.StorageBackend = "file"
	}
	if cfg.StorageBackend != "file" && cfg.StorageBackend != "etcd" {
		log.Fatalf("unsupported storage backend: %s (supported: file, etcd)", cfg.StorageBackend)
	}
	cfg.ClusterSyncURL = strings.TrimRight(strings.TrimSpace(cfg.ClusterSyncURL), "/")
	cfg.ClusterSyncURLs = configClusterSyncURLs(cfg.ClusterSyncURL, cfg.ClusterSyncURLs)
	if len(cfg.ClusterSyncURLs) > 0 {
		cfg.ClusterSyncURL = cfg.ClusterSyncURLs[0]
		if strings.TrimSpace(cfg.ClusterSyncUsername) == "" || strings.TrimSpace(cfg.ClusterSyncPassword) == "" {
			log.Fatalf("cluster sync requires CLUSTER_SYNC_USERNAME and CLUSTER_SYNC_PASSWORD when CLUSTER_SYNC_URL/CLUSTER_SYNC_URLS is set")
		}
		for _, endpoint := range cfg.ClusterSyncURLs {
			parsed, err := neturl.Parse(endpoint)
			if err != nil || strings.ToLower(strings.TrimSpace(parsed.Scheme)) != "https" {
				log.Fatalf("cluster sync requires HTTPS endpoint, got %q", endpoint)
			}
		}
	}

	if err := os.MkdirAll(filepath.Dir(cfg.DataFile), 0o755); err != nil {
		log.Fatalf("failed to create data dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.SettingsFile), 0o755); err != nil {
		log.Fatalf("failed to create settings data dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.AdminAuthFile), 0o755); err != nil {
		log.Fatalf("failed to create admin auth data dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.CertDataFile), 0o755); err != nil {
		log.Fatalf("failed to create cert data dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.AccessLogFile), 0o755); err != nil {
		log.Fatalf("failed to create access log data dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.NodeDataFile), 0o755); err != nil {
		log.Fatalf("failed to create node data dir: %v", err)
	}
	if err := os.MkdirAll(cfg.BackupDir, 0o755); err != nil {
		log.Fatalf("failed to create backup dir: %v", err)
	}
	if err := os.MkdirAll(cfg.CertDir, 0o755); err != nil {
		log.Fatalf("failed to create cert dir: %v", err)
	}

	siteBlob := persist.BlobStore(persist.NewFileBlobStore(cfg.DataFile))
	settingsBlob := persist.BlobStore(persist.NewFileBlobStore(cfg.SettingsFile))
	nodeBlob := persist.BlobStore(persist.NewFileBlobStore(cfg.NodeDataFile))
	certBlob := persist.BlobStore(persist.NewFileBlobStore(cfg.CertDataFile))
	var etcdFactory *persist.EtcdFactory
	if cfg.StorageBackend == "etcd" {
		etcdFactory, err = persist.NewEtcdFactory(persist.EtcdOptions{
			Endpoints:   cfg.StorageEtcdEndpoints,
			Prefix:      cfg.StorageEtcdPrefix,
			DialTimeout: cfg.StorageEtcdDialTimeout,
		})
		if err != nil {
			log.Fatalf("failed to initialize etcd storage: %v", err)
		}
		defer func() {
			if closeErr := etcdFactory.Close(); closeErr != nil {
				log.Printf("etcd storage close failed: %v", closeErr)
			}
		}()
		siteBlob = etcdFactory.Blob("sites")
		settingsBlob = etcdFactory.Blob("settings")
		nodeBlob = etcdFactory.Blob("nodes")
		certBlob = etcdFactory.Blob("certificates")
		log.Printf("storage backend: etcd endpoints=%s prefix=%s", strings.Join(cfg.StorageEtcdEndpoints, ","), cfg.StorageEtcdPrefix)
	}
	var controlReadOnly atomic.Bool
	controlReadOnly.Store(len(cfg.ClusterSyncURLs) > 0)
	var leaderElector *persist.LeaderElector
	var leaderSwitchCount atomic.Uint64
	var leaderLastEventMu sync.Mutex
	var leaderLastEventAt time.Time
	var leaderLastEventKind string
	var leaderRecentEvents []time.Time
	var leaderFlappingAlertAt time.Time
	const leaderFlappingWindow = 60 * time.Second
	const leaderFlappingThreshold = 4
	const leaderFlappingAlertCooldown = 2 * time.Minute
	if cfg.StorageBackend == "etcd" && len(cfg.ClusterSyncURLs) == 0 && etcdFactory != nil {
		controlReadOnly.Store(true)
		leaderCtx, leaderCancel := context.WithCancel(context.Background())
		defer leaderCancel()
		leaderElector = persist.NewLeaderElector(etcdFactory.Client(), etcdFactory.Prefix(), cfg.NodeID, 10)
		go leaderElector.Run(leaderCtx, &controlReadOnly)
	}

	st, err := store.NewWithBlob(siteBlob)
	if err != nil {
		log.Fatalf("failed to open store: %v", err)
	}
	nodeStore, err := node.NewWithBlob(nodeBlob)
	if err != nil {
		log.Fatalf("failed to open node store: %v", err)
	}
	if _, err := nodeStore.TouchHeartbeat(cfg.NodeID, cfg.NodeName, cfg.AdminAddr, nil, true); err != nil {
		log.Fatalf("failed to initialize local node: %v", err)
	}
	accessLogStore, err := proxy.NewAccessLogStore(cfg.AccessLogFile, proxy.AccessLogStoreOptions{
		MaxRows:      cfg.AccessLogMaxRows,
		RetentionTTL: cfg.AccessLogTTL,
		FlushEvery:   cfg.AccessLogFlush,
	})
	if err != nil {
		log.Fatalf("failed to open access log store: %v", err)
	}
	defer func() {
		if err := accessLogStore.Close(); err != nil {
			log.Printf("access log store close failed: %v", err)
		}
	}()

	router := proxy.NewRouter()
	defer router.Close()
	l4Proxy := proxy.NewL4Proxy()
	router.SetAccessLogStore(accessLogStore)
	if err := router.SetTrustedProxyCIDRs(cfg.TrustedProxyCIDRs); err != nil {
		log.Fatalf("failed to configure trusted proxy cidrs: %v", err)
	}
	localSites := filterSitesForNode(st.List(), cfg.NodeID)
	httpSites := filterHTTPSites(localSites)
	if err := router.Load(httpSites); err != nil {
		log.Fatalf("failed to load router config: %v", err)
	}

	var acmePool *acmeManagerPool
	if cfg.EnableAutoTLS {
		acmePool = newACMEManagerPool(cfg, router)
	}

	certManager, err := certmgr.NewWithBlob(certBlob, cfg.CertDir, certmgr.Options{
		EnableAutoTLS: cfg.EnableAutoTLS,
		IssueACME: func(ctx context.Context, domain string, acmeCfg certmgr.ACMEConfig) (*x509.Certificate, error) {
			if acmePool == nil {
				return nil, errors.New("auto tls is disabled")
			}
			return acmePool.Issue(ctx, domain, acmeCfg)
		},
		LoadACMECache: func(domain string) (*x509.Certificate, error) {
			return certmgr.LoadACMECachedCertificate(cfg.CertDir, domain)
		},
	})
	if err != nil {
		log.Fatalf("failed to open certificate store: %v", err)
	}
	defer certManager.Close()

	defaultAdminPort, err := portNumber(cfg.AdminAddr)
	if err != nil {
		defaultAdminPort = 9000
	}
	defaultAdminTLSPort, err := portNumber(cfg.AdminHTTPSAddr)
	if err != nil {
		defaultAdminTLSPort = 9443
	}
	settingsStore, err := settings.NewWithBlob(settingsBlob, settings.Settings{
		Language: "en",
		WebPort:  defaultAdminPort,
		ClusterSync: settings.ClusterSync{
			CertificateSyncEnabled:       true,
			FailCloseEnabled:             true,
			FailCloseConsecutiveFailures: 10,
			FailCloseStaleAfter:          "5m",
		},
		Alert: settings.Alert{
			WebhookURL:     cfg.AlertWebhookURL,
			Consecutive5xx: cfg.AlertConsecutive5xx,
			LatencyMs:      cfg.AlertLatencyMs,
			Cooldown:       cfg.AlertCooldown.String(),
		},
		AdminTLS: settings.AdminTLS{
			Enabled:        strings.TrimSpace(cfg.AdminHTTPSAddr) != "",
			HTTPSPort:      defaultAdminTLSPort,
			RedirectHTTP:   cfg.AdminTLSRedirectHTTP,
			AutoSelfSigned: cfg.AdminTLSAutoSelfSigned,
			CertificateID:  cfg.AdminTLSCertificateID,
			CertFile:       cfg.AdminTLSCertFile,
			KeyFile:        cfg.AdminTLSKeyFile,
		},
	})
	if err != nil {
		log.Fatalf("failed to open settings store: %v", err)
	}
	if cfg.StorageBackend == "etcd" && fileCfg != nil {
		if err := applyDeclarativeDataToStores(fileCfg, st, settingsStore, certManager); err != nil {
			log.Fatalf("failed to apply declarative config into etcd storage: %v", err)
		}
	}
	currentSettings := settingsStore.Get()
	syncMode := clustersync.ModeController
	if len(cfg.ClusterSyncURLs) > 0 {
		syncMode = clustersync.ModeFollower
		if err := validateFollowerSyncedSettings(currentSettings); err != nil {
			log.Fatalf("invalid follower synced settings: %v", err)
		}
	}
	clusterSyncRuntime := clustersync.NewRuntimeState(syncMode, currentSettings.ClusterSync, cfg.ClusterSyncInterval)
	applyRuntimeOverridesFromSettings(&cfg, currentSettings)
	runtimeSites, err := iprules.ResolveSitesForRuntime(filterSitesForNode(st.List(), cfg.NodeID), currentSettings)
	if err != nil {
		log.Fatalf("failed to resolve site ip rules: %v", err)
	}
	if err := router.Load(filterHTTPSites(runtimeSites)); err != nil {
		log.Fatalf("failed to load router config with ip rules: %v", err)
	}
	alertDispatcher := newAlertDispatcher(router)
	defer alertDispatcher.Close()
	alertDispatcher.Apply(currentSettings.Alert)
	if leaderElector != nil {
		leaderElector.SetEventHook(func(kind string, detail map[string]string) {
			now := time.Now().UTC()
			leaderSwitchCount.Add(1)
			leaderLastEventMu.Lock()
			leaderLastEventAt = now
			leaderLastEventKind = strings.TrimSpace(kind)
			cutoff := now.Add(-leaderFlappingWindow)
			next := leaderRecentEvents[:0]
			for _, ts := range leaderRecentEvents {
				if ts.After(cutoff) || ts.Equal(cutoff) {
					next = append(next, ts)
				}
			}
			leaderRecentEvents = append(next, now)
			recentCount := len(leaderRecentEvents)
			canAlertFlapping := recentCount >= leaderFlappingThreshold && (leaderFlappingAlertAt.IsZero() || now.Sub(leaderFlappingAlertAt) >= leaderFlappingAlertCooldown)
			if canAlertFlapping {
				leaderFlappingAlertAt = now
			}
			leaderLastEventMu.Unlock()
			payload := map[string]any{
				"nodeId": cfg.NodeID,
			}
			for k, v := range detail {
				payload[k] = v
			}
			log.Printf("ha event: kind=%s detail=%v", kind, detail)
			alertDispatcher.Emit(kind, payload)
			if canAlertFlapping {
				alertDispatcher.Emit("ha_leader_flapping", map[string]any{
					"nodeId":        cfg.NodeID,
					"windowSeconds": int(leaderFlappingWindow.Seconds()),
					"threshold":     leaderFlappingThreshold,
					"recentCount":   recentCount,
				})
			}
		})
	}
	var settingsRuntimeMu sync.Mutex

	backupManager, err := backup.New(backup.Options{
		BackupDir:     cfg.BackupDir,
		DataFile:      cfg.DataFile,
		SettingsFile:  cfg.SettingsFile,
		CertDataFile:  cfg.CertDataFile,
		AdminAuthFile: cfg.AdminAuthFile,
		AccessLogFile: cfg.AccessLogFile,
		CertDir:       cfg.CertDir,
	}, currentSettings.Backup)
	if err != nil {
		log.Fatalf("failed to initialize backup manager: %v", err)
	}
	defer backupManager.Close()

	if err := validateAdminSecurity(cfg, currentSettings); err != nil {
		log.Fatalf("invalid admin security configuration: %v", err)
	}

	adminAccess, err := newAdminAccessController(currentSettings)
	if err != nil {
		log.Fatalf("failed to initialize admin access rules: %v", err)
	}
	accountStore, bootstrapRecoveryCode, err := adminauth.NewStore(cfg.AdminAuthFile, cfg.AdminUsername, cfg.AdminPassword)
	if err != nil {
		log.Fatalf("failed to initialize admin auth store: %v", err)
	}
	if err := validateAdminCredentialStrength(cfg, currentSettings, accountStore); err != nil {
		log.Printf("warning: insecure admin credential configuration: %v", err)
	}
	if err := validateAdminTLSConfig(cfg); err != nil {
		log.Fatalf("invalid admin tls configuration: %v", err)
	}
	if bootstrapRecoveryCode != "" {
		log.Printf("admin recovery code initialized: %s (store this code securely)", bootstrapRecoveryCode)
	}
	adminAuth := adminauth.NewManager(accountStore)
	proxyRuntimeHandler := clusterSyncFailCloseMiddleware(clusterSyncRuntime, router)
	customPortManager := newCustomPortManager(proxyRuntimeHandler)
	var adminManager *adminServerManager
	var adminTLSManager *adminTLSServerManager
	adminTLSRedirectPolicy := newAdminTLSRedirectPolicy()
	adminTLSRedirectPolicy.Apply(cfg)
	syncCustomPorts := func(items []site.Site) {
		localItems := filterSitesForNode(items, cfg.NodeID)
		settingsRuntimeMu.Lock()
		adminAddr := cfg.AdminAddr
		adminHTTPSAddr := cfg.AdminHTTPSAddr
		autoTLS := cfg.EnableAutoTLS
		httpAddr := cfg.HTTPAddr
		httpsAddr := cfg.HTTPSAddr
		settingsRuntimeMu.Unlock()
		if adminManager != nil {
			adminAddr = adminManager.CurrentAddr()
		}
		reserved := reservedListenPorts(adminAddr, adminHTTPSAddr, httpAddr, httpsAddr, autoTLS)
		l4Sites := proxy.ExtractL4Sites(localItems)
		for _, l4 := range l4Sites {
			reserved[l4.Port] = struct{}{}
		}
		customPortManager.Sync(localItems, reserved)
		l4Proxy.Sync(l4Sites, nil)
	}

	applySettingsRuntime := func(updated settings.Settings) error {
		if len(cfg.ClusterSyncURLs) > 0 {
			if err := validateFollowerSyncedSettings(updated); err != nil {
				return err
			}
		}
		clusterSyncRuntime.UpdateConfig(updated.ClusterSync)
		if err := backupManager.ApplySchedule(updated.Backup); err != nil {
			return fmt.Errorf("backup schedule update failed: %w", err)
		}
		if err := adminAccess.Update(updated); err != nil {
			return fmt.Errorf("admin access rule update failed: %w", err)
		}
		settingsRuntimeMu.Lock()
		oldCfg := cfg
		nextCfg := cfg
		settingsRuntimeMu.Unlock()
		applyRuntimeOverridesFromSettings(&nextCfg, updated)
		currentAdminAddr := adminManager.CurrentAddr()
		targetAddr := addrWithPort(currentAdminAddr, updated.WebPort)
		if err := adminManager.SwitchAddr(targetAddr); err != nil {
			return fmt.Errorf("admin web port switch failed to %s: %w", targetAddr, err)
		}
		nextCfg.AdminAddr = targetAddr
		if updated.AdminTLS.Enabled {
			nextCfg.AdminHTTPSAddr = addrWithPort(targetAddr, updated.AdminTLS.HTTPSPort)
		} else {
			nextCfg.AdminHTTPSAddr = ""
		}
		adminTLSRedirectPolicy.Apply(nextCfg)
		if err := adminTLSManager.Apply(nextCfg); err != nil {
			adminTLSRedirectPolicy.Apply(oldCfg)
			if rollbackErr := adminManager.SwitchAddr(currentAdminAddr); rollbackErr != nil {
				log.Printf("admin web port rollback failed to %s: %v", currentAdminAddr, rollbackErr)
			}
			if rollbackErr := adminTLSManager.Apply(oldCfg); rollbackErr != nil {
				log.Printf("admin https rollback failed: %v", rollbackErr)
			}
			return fmt.Errorf("admin https apply failed: %w", err)
		}
		alertDispatcher.Apply(updated.Alert)
		settingsRuntimeMu.Lock()
		cfg = nextCfg
		currentSettings = updated
		settingsRuntimeMu.Unlock()
		resolvedSites, err := iprules.ResolveSitesForRuntime(filterSitesForNode(st.List(), cfg.NodeID), updated)
		if err != nil {
			return fmt.Errorf("site ip rule resolve failed after settings update: %w", err)
		}
		if err := router.Load(filterHTTPSites(resolvedSites)); err != nil {
			return fmt.Errorf("router reload failed after settings update: %w", err)
		}
		syncCustomPorts(st.List())
		return nil
	}

	countryUpdater := ipcountry.NewUpdater(settingsStore, func(updated settings.Settings) {
		if err := applySettingsRuntime(updated); err != nil {
			log.Printf("country ip runtime apply failed: %v", err)
		}
	})
	defer countryUpdater.Close()
	startSharedStateSync(st, nodeStore, router, settingsStore, cfg.NodeID, syncCustomPorts)
	if len(cfg.ClusterSyncURLs) == 0 {
		localNodeHeartbeatStop := startLocalNodeHeartbeat(nodeStore, cfg.NodeID, cfg.NodeName, cfg.AdminAddr)
		defer localNodeHeartbeatStop()
	} else {
		startClusterSync(cfg, st, nodeStore, settingsStore, certManager, applySettingsRuntime, clusterSyncRuntime)
	}

	adminMux := http.NewServeMux()
	apiServer := api.New(st, router, certManager, settingsStore, backupManager, nodeStore, cfg.NodeID, len(cfg.ClusterSyncURLs) > 0, syncCustomPorts, func(updated settings.Settings) error {
		if err := applySettingsRuntime(updated); err != nil {
			return err
		}
		countryUpdater.Trigger()
		return nil
	}, func() clustersync.RuntimeStatus {
		status := clusterSyncRuntime.Snapshot(time.Now().UTC())
		status.ControlWritable = !controlReadOnly.Load()
		return status
	})
	apiServer.SetReadOnlyControlFunc(func() bool {
		return controlReadOnly.Load()
	})
	apiServer.SetReadOnlyControlErrorFunc(func() map[string]string {
		out := map[string]string{
			"message": "control plane is read-only on this node",
		}
		if cfg.StorageBackend == "etcd" && len(cfg.ClusterSyncURLs) == 0 {
			out["electionMode"] = "etcd_lock"
			out["message"] = "control plane write rejected on non-leader node"
			if leaderElector != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				leaderNodeID, err := leaderElector.CurrentLeader(ctx)
				cancel()
				if err == nil && strings.TrimSpace(leaderNodeID) != "" {
					out["leaderNodeId"] = strings.TrimSpace(leaderNodeID)
				}
			}
		} else if len(cfg.ClusterSyncURLs) > 0 {
			out["electionMode"] = "cluster_sync_follower"
			out["message"] = "control plane write rejected on follower node"
		}
		return out
	})
	apiServer.SetControlPlaneInfoFunc(func() map[string]any {
		info := map[string]any{
			"controlWritable": !controlReadOnly.Load(),
		}
		if cfg.StorageBackend == "etcd" && len(cfg.ClusterSyncURLs) == 0 {
			info["controlElectionMode"] = "etcd_lock"
			info["controlLeaderSwitchCount"] = leaderSwitchCount.Load()
			leaderLastEventMu.Lock()
			cutoff := time.Now().UTC().Add(-leaderFlappingWindow)
			recentCount := 0
			for _, ts := range leaderRecentEvents {
				if ts.After(cutoff) || ts.Equal(cutoff) {
					recentCount++
				}
			}
			info["controlLeaderFlapping"] = recentCount >= leaderFlappingThreshold
			info["controlLeaderRecentEventCount"] = recentCount
			info["controlLeaderFlappingWindowSeconds"] = int(leaderFlappingWindow.Seconds())
			if !leaderLastEventAt.IsZero() {
				info["controlLeaderLastEventAt"] = leaderLastEventAt
			}
			if strings.TrimSpace(leaderLastEventKind) != "" {
				info["controlLeaderLastEventKind"] = leaderLastEventKind
			}
			leaderLastEventMu.Unlock()
			if leaderElector != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				leaderNodeID, err := leaderElector.CurrentLeader(ctx)
				cancel()
				if err != nil {
					info["controlLeaderError"] = err.Error()
				} else {
					info["controlLeaderNodeId"] = leaderNodeID
				}
			}
		}
		return info
	})
	apiServer.Register(adminMux)
	adminMux.HandleFunc("/metrics", func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		leaderNodeID := ""
		electionMode := "standalone"
		if cfg.StorageBackend == "etcd" && len(cfg.ClusterSyncURLs) == 0 {
			electionMode = "etcd_lock"
			if leaderElector != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				currentLeader, err := leaderElector.CurrentLeader(ctx)
				cancel()
				if err == nil {
					leaderNodeID = strings.TrimSpace(currentLeader)
				}
			}
		} else if len(cfg.ClusterSyncURLs) > 0 {
			electionMode = "cluster_sync_follower"
		}
		syncStatus := clusterSyncRuntime.Snapshot(time.Now().UTC())
		leaderLastEventMu.Lock()
		recentCount := 0
		cutoff := time.Now().UTC().Add(-leaderFlappingWindow)
		for _, ts := range leaderRecentEvents {
			if ts.After(cutoff) || ts.Equal(cutoff) {
				recentCount++
			}
		}
		leaderFlapping := recentCount >= leaderFlappingThreshold
		leaderLastEventMu.Unlock()
		metrics := router.PrometheusMetrics() + buildHAMetrics(syncStatus, !controlReadOnly.Load(), electionMode, leaderNodeID, leaderSwitchCount.Load(), cfg.NodeID, leaderFlapping, recentCount)
		_, _ = w.Write([]byte(metrics))
	})
	adminAuth.RegisterRoutes(adminMux)
	if cfg.EnableUI {
		adminMux.HandleFunc("/login", func(w http.ResponseWriter, req *http.Request) {
			http.Redirect(w, req, "/login.html", http.StatusFound)
		})
		adminMux.Handle("/", ui.Handler())
	} else {
		log.Printf("admin UI disabled, API remains available at %s", cfg.AdminAddr)
	}

	adminHandler := adminAccess.Middleware(adminMux)
	adminHandler = adminAuth.Middleware(adminHandler)
	adminHTTPHandler := adminTLSRedirectPolicy.Middleware(adminHandler)
	adminListenAddr := resolveAdminAddr(cfg.AdminAddr)
	adminManager = newAdminServerManager(adminListenAddr, logging(adminHTTPHandler))
	if err := adminManager.SwitchAddr(adminListenAddr); err != nil {
		log.Fatalf("admin server failed: %v", err)
	}
	adminTLSManager = newAdminTLSServerManager(logging(adminHandler), certManager)
	if err := adminTLSManager.Apply(cfg); err != nil {
		log.Fatalf("admin https server failed: %v", err)
	}
	syncCustomPorts(st.List())
	countryUpdater.Start()

	if cfg.EnableAutoTLS {
		startWithAutoTLS(cfg, adminManager, adminTLSManager, router, proxyRuntimeHandler, acmePool, certManager, customPortManager, l4Proxy)
	} else {
		startHTTPOnly(cfg, adminManager, adminTLSManager, proxyRuntimeHandler, customPortManager, l4Proxy)
	}
}

func tryHandleAdminCLI(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}
	switch strings.TrimSpace(args[0]) {
	case "reset-admin":
		return true, runResetAdminCLI(args[1:])
	default:
		return false, nil
	}
}

func runResetAdminCLI(args []string) error {
	fs := flag.NewFlagSet("reset-admin", flag.ContinueOnError)
	username := fs.String("username", "admin", "new admin username")
	password := fs.String("password", "", "new admin password")
	configFile := fs.String("config", "", "optional config file path")
	authFile := fs.String("auth-file", "", "override admin auth file path")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if strings.TrimSpace(*username) == "" {
		return errors.New("--username is required")
	}
	if strings.TrimSpace(*password) == "" {
		return errors.New("--password is required")
	}

	cfg := config.Load()
	if raw := strings.TrimSpace(*configFile); raw != "" {
		cfg.ConfigFile = raw
	}
	fileCfg, err := config.LoadFromFile(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("load config file failed: %w", err)
	}
	if fileCfg != nil {
		if err := cfg.ApplyRuntimeFile(fileCfg.Runtime); err != nil {
			return fmt.Errorf("apply runtime config failed: %w", err)
		}
	}
	if raw := strings.TrimSpace(*authFile); raw != "" {
		cfg.AdminAuthFile = filepath.Clean(raw)
	}

	if err := os.MkdirAll(filepath.Dir(cfg.AdminAuthFile), 0o755); err != nil {
		return fmt.Errorf("create admin auth dir failed: %w", err)
	}
	accountStore, _, err := adminauth.NewStore(cfg.AdminAuthFile, cfg.AdminUsername, cfg.AdminPassword)
	if err != nil {
		return fmt.Errorf("open admin auth store failed: %w", err)
	}
	account, recoveryCode, err := accountStore.ResetCredentialsByCLI(*username, *password)
	if err != nil {
		return fmt.Errorf("reset admin credentials failed: %w", err)
	}

	log.Printf("admin credentials reset successfully")
	log.Printf("admin auth file: %s", cfg.AdminAuthFile)
	log.Printf("username: %s", account.Username)
	log.Printf("recovery hint: %s", account.RecoveryHint)
	log.Printf("new recovery code (store securely): %s", recoveryCode)
	log.Printf("if FlowProxy is running, restart it to apply the new credentials")
	return nil
}

func startHTTPOnly(cfg config.Config, adminServer *adminServerManager, adminTLSServer *adminTLSServerManager, proxyHandler http.Handler, customPorts *customPortManager, l4Proxy *proxy.L4Proxy, extraServers ...*http.Server) {
	httpAddr := resolveHTTPAddr(cfg.HTTPAddr)
	proxyServer := &http.Server{
		Addr:         httpAddr,
		Handler:      logging(proxyHandler),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	log.Printf("proxy (HTTP only) listening on %s", cfg.HTTPAddr)
	go func() {
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("proxy server failed: %v", err)
		}
	}()
	servers := append([]*http.Server{proxyServer}, extraServers...)
	waitForShutdown(customPorts, adminServer, adminTLSServer, l4Proxy, servers...)
}

func startWithAutoTLS(cfg config.Config, adminServer *adminServerManager, adminTLSServer *adminTLSServerManager, proxyRouter *proxy.Router, proxyHandler http.Handler, acmePool *acmeManagerPool, certManager *certmgr.Manager, customPorts *customPortManager, l4Proxy *proxy.L4Proxy, extraServers ...*http.Server) {
	if acmePool == nil {
		log.Fatalf("acme manager pool is required when auto tls is enabled")
	}
	runtimeACME := acmePool.RuntimeManager()
	if runtimeACME == nil {
		log.Fatalf("runtime acme manager is not initialized")
	}
	httpAddr := resolveHTTPAddr(cfg.HTTPAddr)
	httpsAddr := resolveHTTPSAddr(cfg.HTTPSAddr)
	httpServer := &http.Server{
		Addr:         httpAddr,
		Handler:      acmePool.HTTPHandler(redirectToHTTPSHandler(cfg.HTTPSAddr)),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	httpsServer := &http.Server{
		Addr:         httpsAddr,
		Handler:      logging(proxyHandler),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second,
		TLSConfig: &tls.Config{
			GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if certManager != nil {
					if boundID := proxyRouter.CertificateIDForHost(hello.ServerName); boundID != "" {
						cert, err := certManager.GetTLSCertificateByID(boundID)
						if err == nil && cert != nil {
							return cert, nil
						}
						if err != nil {
							log.Printf("bound certificate %s for %s unavailable: %v", boundID, hello.ServerName, err)
						}
					}
					cert, err := certManager.MatchTLSCertificate(hello.ServerName)
					if err == nil && cert != nil {
						return cert, nil
					}
				}
				return runtimeACME.GetCertificate(hello)
			},
			MinVersion: tls.VersionTLS12,
		},
	}

	log.Printf("proxy HTTP listening on %s", cfg.HTTPAddr)
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server failed: %v", err)
		}
	}()

	log.Printf("proxy HTTPS listening on %s", cfg.HTTPSAddr)
	go func() {
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("https server failed: %v", err)
		}
	}()

	servers := append([]*http.Server{httpServer, httpsServer}, extraServers...)
	waitForShutdown(customPorts, adminServer, adminTLSServer, l4Proxy, servers...)
}

func redirectToHTTPSHandler(httpsAddr string) http.Handler {
	httpsPort := listenerPort(httpsAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		targetHost := redirectHost(req.Host, httpsPort)
		target := "https://" + targetHost + req.URL.RequestURI()
		http.Redirect(w, req, target, http.StatusMovedPermanently)
	})
}

func listenerPort(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return strings.TrimPrefix(addr, ":")
	}
	if _, err := strconv.Atoi(addr); err == nil {
		return addr
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return port
}

func redirectHost(requestHost string, httpsPort string) string {
	host, _, err := net.SplitHostPort(requestHost)
	if err != nil {
		trimmed := strings.TrimSpace(requestHost)
		switch {
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			host = strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")
		default:
			host = trimmed
		}
	}
	if host == "" {
		host = requestHost
	}

	if httpsPort == "" || httpsPort == "443" {
		return host
	}
	return net.JoinHostPort(host, httpsPort)
}

func addrWithPort(addr string, port int) string {
	if port < 1 || port > 65535 {
		return addr
	}
	value := strings.TrimSpace(addr)
	if value == "" || strings.HasPrefix(value, ":") {
		return fmt.Sprintf(":%d", port)
	}
	if _, err := strconv.Atoi(value); err == nil {
		return fmt.Sprintf(":%d", port)
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Sprintf(":%d", port)
	}
	if host == "" {
		return fmt.Sprintf(":%d", port)
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func portNumber(addr string) (int, error) {
	raw := listenerPort(addr)
	if raw == "" {
		return 0, errors.New("listen port is empty")
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > 65535 {
		return 0, fmt.Errorf("invalid listen port: %s", raw)
	}
	return value, nil
}

func waitForShutdown(customPorts *customPortManager, adminServer *adminServerManager, adminTLSServer *adminTLSServerManager, l4Proxy *proxy.L4Proxy, servers ...*http.Server) {
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGTERM)

	<-done
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if customPorts != nil {
		customPorts.Shutdown(ctx)
	}
	if l4Proxy != nil {
		l4Proxy.Shutdown(ctx)
	}
	if adminServer != nil {
		adminServer.Shutdown(ctx)
	}
	if adminTLSServer != nil {
		adminTLSServer.Shutdown(ctx)
	}
	for _, srv := range servers {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
	}
}

type adminServerManager struct {
	mu           sync.Mutex
	addr         string
	handler      http.Handler
	readTimeout  time.Duration
	writeTimeout time.Duration
	server       *http.Server
}

func newAdminServerManager(addr string, handler http.Handler) *adminServerManager {
	return &adminServerManager{
		addr:         addr,
		handler:      handler,
		readTimeout:  10 * time.Second,
		writeTimeout: 30 * time.Second,
	}
}

func (m *adminServerManager) CurrentAddr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.addr
}

func (m *adminServerManager) SwitchAddr(addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return errors.New("admin address is empty")
	}
	m.mu.Lock()
	if addr == m.addr && m.server != nil {
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	m.mu.Lock()
	if addr == m.addr && m.server != nil {
		m.mu.Unlock()
		_ = listener.Close()
		return nil
	}
	oldServer := m.server
	oldAddr := m.addr
	newServer := &http.Server{
		Addr:         addr,
		Handler:      m.handler,
		ReadTimeout:  m.readTimeout,
		WriteTimeout: m.writeTimeout,
	}
	m.server = newServer
	m.addr = addr
	m.mu.Unlock()

	log.Printf("admin UI listening on %s", addr)
	go func(target string, srv *http.Server, ln net.Listener) {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("admin server failed on %s: %v", target, err)
		}
	}(addr, newServer, listener)

	if oldServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := oldServer.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("admin server shutdown failed on %s: %v", oldAddr, err)
		}
		cancel()
	}
	return nil
}

func (m *adminServerManager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	server := m.server
	addr := m.addr
	m.server = nil
	m.mu.Unlock()
	if server == nil {
		return
	}
	if err := server.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
		log.Printf("admin server shutdown failed on %s: %v", addr, err)
	}
}

type adminAuthController struct {
	username string
	password string
}

func newAdminAuthController(username string, password string) *adminAuthController {
	user := strings.TrimSpace(username)
	pass := strings.TrimSpace(password)
	if user == "" || pass == "" {
		return nil
	}
	return &adminAuthController{
		username: user,
		password: pass,
	}
}

func (c *adminAuthController) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		user, pass, ok := req.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(c.username)) != 1 || subtle.ConstantTimeCompare([]byte(pass), []byte(c.password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="FlowProxy Admin"`)
			http.Error(w, "admin authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}

type adminAccessController struct {
	mu    sync.RWMutex
	allow []adminIPRule
	deny  []adminIPRule
}

type adminIPRule struct {
	ip  net.IP
	net *net.IPNet
}

func newAdminAccessController(cfg settings.Settings) (*adminAccessController, error) {
	controller := &adminAccessController{}
	if err := controller.Update(cfg); err != nil {
		return nil, err
	}
	return controller, nil
}

func (c *adminAccessController) Update(cfg settings.Settings) error {
	allow, err := parseAdminIPRules(cfg.WebAccess.AllowCIDRs)
	if err != nil {
		return err
	}
	deny, err := parseAdminIPRules(cfg.WebAccess.DenyCIDRs)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.allow = allow
	c.deny = deny
	c.mu.Unlock()
	return nil
}

func (c *adminAccessController) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		clientIP := adminClientIP(req)
		c.mu.RLock()
		reject := adminDenied(c.allow, c.deny, clientIP)
		c.mu.RUnlock()
		if reject {
			http.Error(w, "admin access denied", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func parseAdminIPRules(items []string) ([]adminIPRule, error) {
	out := make([]adminIPRule, 0, len(items))
	for _, item := range items {
		candidate := strings.TrimSpace(item)
		if candidate == "" {
			continue
		}
		if strings.Contains(candidate, "/") {
			_, network, err := net.ParseCIDR(candidate)
			if err != nil {
				return nil, err
			}
			out = append(out, adminIPRule{net: network})
			continue
		}
		ip := net.ParseIP(candidate)
		if ip == nil {
			return nil, fmt.Errorf("invalid ip: %s", candidate)
		}
		out = append(out, adminIPRule{ip: ip})
	}
	return out, nil
}

func adminDenied(allow []adminIPRule, deny []adminIPRule, ipText string) bool {
	ip := net.ParseIP(ipText)
	if ip == nil {
		return len(allow) > 0
	}
	if len(allow) > 0 && !adminMatchAny(allow, ip) {
		return true
	}
	if len(deny) > 0 && adminMatchAny(deny, ip) {
		return true
	}
	return false
}

func adminMatchAny(rules []adminIPRule, ip net.IP) bool {
	for _, rule := range rules {
		if rule.net != nil && rule.net.Contains(ip) {
			return true
		}
		if rule.ip != nil && rule.ip.Equal(ip) {
			return true
		}
	}
	return false
}

func adminClientIP(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

func validateAdminSecurity(cfg config.Config, current settings.Settings) error {
	user := strings.TrimSpace(cfg.AdminUsername)
	pass := strings.TrimSpace(cfg.AdminPassword)
	if (user == "") != (pass == "") {
		return errors.New("ADMIN_USERNAME and ADMIN_PASSWORD must be configured together")
	}
	// NOTE: Security guard disabled by default per project requirement:
	// do not hard-fail startup when admin binds to public addresses without auth/IP allowlist.
	_ = current
	return nil
}

func validateAdminCredentialStrength(cfg config.Config, current settings.Settings, accountStore *adminauth.Store) error {
	if accountStore == nil {
		return nil
	}
	if !adminListenIsPublic(cfg.AdminAddr) {
		return nil
	}
	if len(current.WebAccess.AllowCIDRs) > 0 {
		return nil
	}
	account := accountStore.Snapshot()
	if accountStore.VerifyCredentials(account.Username, "admin") {
		return errors.New("public admin endpoint cannot use the default admin password without an IP allowlist")
	}
	return nil
}

func adminListenIsPublic(addr string) bool {
	value := strings.TrimSpace(addr)
	if value == "" {
		return true
	}
	if strings.HasPrefix(value, ":") {
		return true
	}
	if _, err := strconv.Atoi(value); err == nil {
		return true
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return true
	}
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return !ip.IsLoopback()
	}
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost":
		return false
	default:
		return true
	}
}

// filterHTTPSites filters out L4 port forwarding sites from the list.
func filterHTTPSites(sites []site.Site) []site.Site {
	var out []site.Site
	for _, s := range sites {
		if proxy.IsL4Site(s) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// resolveHTTPAddr resolves interface binding for the HTTP proxy listen address.
func resolveHTTPAddr(raw string) string {
	addr, err := normalizeBindAddr(raw, 80)
	if err != nil {
		return raw
	}
	return addr
}

// resolveHTTPSAddr resolves interface binding for the HTTPS proxy listen address.
func resolveHTTPSAddr(raw string) string {
	addr, err := normalizeBindAddr(raw, 443)
	if err != nil {
		return raw
	}
	return addr
}

// resolveAdminAddr resolves interface binding for the admin listen address.
func resolveAdminAddr(raw string) string {
	addr, err := normalizeBindAddr(raw, 9000)
	if err != nil {
		return raw
	}
	return addr
}

type customPortManager struct {
	mu      sync.Mutex
	handler http.Handler
	servers map[string]*http.Server // key = "port" or "interface:port"
}

type portServer struct {
	key    string
	server *http.Server
}

func newCustomPortManager(handler http.Handler) *customPortManager {
	return &customPortManager{
		handler: handler,
		servers: map[string]*http.Server{},
	}
}

func (m *customPortManager) Sync(sites []site.Site, reserved map[int]struct{}) {
	type portTarget struct {
		key     string
		address string
		port    int
	}
	want := map[string]portTarget{}
	for _, item := range sites {
		if !item.Enabled || item.ListenPort <= 0 {
			continue
		}
		if proxy.IsL4Site(item) {
			continue
		}
		if _, blocked := reserved[item.ListenPort]; blocked {
			continue
		}
		ifaces := m.effectiveInterfaces(item)
		for _, iface := range ifaces {
			addr := m.buildListenAddrFromIface(iface, item.ListenPort)
			key := m.portKeyFromIface(iface, item.ListenPort)
			want[key] = portTarget{key: key, address: addr, port: item.ListenPort}
		}
	}

	toStop := make([]portServer, 0)
	toStart := make([]portServer, 0)

	m.mu.Lock()
	for key, srv := range m.servers {
		if _, ok := want[key]; ok {
			continue
		}
		toStop = append(toStop, portServer{key: key, server: srv})
		delete(m.servers, key)
	}
	for _, target := range want {
		if _, ok := m.servers[target.key]; ok {
			continue
		}
		server := &http.Server{
			Addr:         target.address,
			Handler:      logging(m.handler),
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 60 * time.Second,
		}
		m.servers[target.key] = server
		toStart = append(toStart, portServer{key: target.key, server: server})
	}
	m.mu.Unlock()

	for _, item := range toStop {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := item.server.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("custom proxy listener %s shutdown failed: %v", item.key, err)
		}
		cancel()
		log.Printf("custom proxy listener stopped: %s", item.key)
	}

	for _, item := range toStart {
		log.Printf("custom proxy listener listening on %s", item.server.Addr)
		go func(srv *http.Server) {
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("custom proxy listener failed on %s: %v", srv.Addr, err)
				m.mu.Lock()
				for k, v := range m.servers {
					if v == srv {
						delete(m.servers, k)
						break
					}
				}
				m.mu.Unlock()
			}
		}(item.server)
	}
}

func (m *customPortManager) effectiveInterfaces(item site.Site) []string {
	if len(item.BindInterfaces) > 0 {
		out := make([]string, 0, len(item.BindInterfaces))
		for _, iface := range item.BindInterfaces {
			iface = strings.TrimSpace(iface)
			if iface == "" {
				continue
			}
			// Validate interface exists
			if _, err := net.InterfaceByName(iface); err == nil {
				out = append(out, iface)
			} else {
				log.Printf("custom port: interface %q not found for site %s, skipping", iface, item.ID)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return []string{""} // empty = all interfaces
}

func (m *customPortManager) buildListenAddrFromIface(iface string, port int) string {
	if iface != "" {
		// Resolve interface name to IP address
		ip, err := ResolveInterfaceAnyIP(iface)
		if err == nil && ip != "" {
			return net.JoinHostPort(ip, strconv.Itoa(port))
		}
		return fmt.Sprintf(":%d", port)
	}
	return fmt.Sprintf(":%d", port)
}

func (m *customPortManager) portKeyFromIface(iface string, port int) string {
	if iface != "" {
		return fmt.Sprintf("%s:%d", iface, port)
	}
	return strconv.Itoa(port)
}

func (m *customPortManager) Shutdown(ctx context.Context) {
	toStop := make([]portServer, 0)
	m.mu.Lock()
	for key, srv := range m.servers {
		toStop = append(toStop, portServer{key: key, server: srv})
	}
	m.servers = map[string]*http.Server{}
	m.mu.Unlock()

	for _, item := range toStop {
		if err := item.server.Shutdown(ctx); err != nil && err != http.ErrServerClosed {
			log.Printf("custom proxy listener %s shutdown failed: %v", item.key, err)
		}
	}
}

func reservedListenPorts(adminAddr string, adminHTTPSAddr string, httpAddr string, httpsAddr string, autoTLS bool) map[int]struct{} {
	out := map[int]struct{}{}
	addresses := []string{adminAddr, adminHTTPSAddr, httpAddr}
	if autoTLS {
		addresses = append(addresses, httpsAddr)
	}
	for _, addr := range addresses {
		port := listenerPort(addr)
		if port == "" {
			continue
		}
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			continue
		}
		out[p] = struct{}{}
	}
	return out
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, req)
		log.Printf("%s %s %s", req.Method, req.URL.Path, time.Since(start).Truncate(time.Millisecond))
	})
}

func filterSitesForNode(items []site.Site, nodeID string) []site.Site {
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

func startLocalNodeHeartbeat(store *node.Store, nodeID string, nodeName string, endpoint string) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if _, err := store.TouchHeartbeat(nodeID, nodeName, endpoint, nil, true); err != nil {
					log.Printf("node heartbeat failed: %v", err)
				}
			case <-stop:
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

func startSharedStateSync(siteStore *store.Store, nodeStore *node.Store, router *proxy.Router, settingsStore *settings.Store, nodeID string, syncCustomPorts func([]site.Site)) {
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := siteStore.Reload(); err != nil {
				log.Printf("shared site store reload failed: %v", err)
				continue
			}
			if nodeStore != nil {
				if err := nodeStore.Reload(); err != nil {
					log.Printf("shared node store reload failed: %v", err)
				}
			}
			items := siteStore.List()
			runtimeSites, err := iprules.ResolveSitesForRuntime(filterSitesForNode(items, nodeID), settingsStore.Get())
			if err != nil {
				log.Printf("shared site resolve failed: %v", err)
				continue
			}
			if err := router.Load(runtimeSites); err != nil {
				log.Printf("shared router reload failed: %v", err)
				continue
			}
			syncCustomPorts(items)
		}
	}()
}

const (
	clusterSyncMaxBackoffMultiplier = 16
	clusterSyncMaxDelay             = 60 * time.Second
	clusterSyncMinDelay             = 500 * time.Millisecond
	clusterSyncJitterDivisor        = 5 // +/-20%
	clusterSyncDigestUninitialized  = "__cluster_sync_digest_uninitialized__"
)

type clusterSyncCertificateCacheEntry struct {
	cacheKey            string
	bundleZIP           []byte
	materialUnavailable bool
}

type clusterSyncLoopState struct {
	certificateCache            map[string]clusterSyncCertificateCacheEntry
	appliedCertificateSetDigest string
}

func newClusterSyncLoopState() *clusterSyncLoopState {
	return &clusterSyncLoopState{
		certificateCache:            map[string]clusterSyncCertificateCacheEntry{},
		appliedCertificateSetDigest: clusterSyncDigestUninitialized,
	}
}

func nextClusterSyncDelay(baseInterval time.Duration, consecutiveFailures int, jitterUnit float64) time.Duration {
	if baseInterval <= 0 {
		baseInterval = 3 * time.Second
	}
	delay := baseInterval
	if consecutiveFailures > 0 {
		multiplier := 1
		for i := 1; i < consecutiveFailures && multiplier < clusterSyncMaxBackoffMultiplier; i++ {
			multiplier *= 2
		}
		if multiplier > clusterSyncMaxBackoffMultiplier {
			multiplier = clusterSyncMaxBackoffMultiplier
		}
		delay = baseInterval * time.Duration(multiplier)
		if delay > clusterSyncMaxDelay {
			delay = clusterSyncMaxDelay
		}
	}
	if !(jitterUnit >= 0 && jitterUnit < 1) {
		jitterUnit = 0.5
	}
	jitterRange := delay / clusterSyncJitterDivisor
	if jitterRange > 0 {
		shift := time.Duration((jitterUnit*2 - 1) * float64(jitterRange))
		delay += shift
	}
	if delay < clusterSyncMinDelay {
		delay = clusterSyncMinDelay
	}
	return delay
}

func clusterSyncCertificateCacheKey(certificate certmgr.Certificate) string {
	domains := make([]string, 0, len(certificate.Domains))
	for _, item := range certificate.Domains {
		value := strings.ToLower(strings.TrimSpace(item))
		if value == "" {
			continue
		}
		domains = append(domains, value)
	}
	slices.Sort(domains)

	updatedAt := ""
	if !certificate.UpdatedAt.IsZero() {
		updatedAt = certificate.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	notAfter := ""
	if !certificate.NotAfter.IsZero() {
		notAfter = certificate.NotAfter.UTC().Format(time.RFC3339Nano)
	}

	return strings.Join([]string{
		strings.TrimSpace(certificate.ID),
		strings.ToLower(strings.TrimSpace(certificate.Type)),
		strings.ToLower(strings.TrimSpace(certificate.Status)),
		updatedAt,
		notAfter,
		strings.TrimSpace(certificate.Serial),
		strings.TrimSpace(certificate.LastError),
		strings.Join(domains, ","),
	}, "|")
}

func clusterSyncCertificateSetDigest(items []certmgr.Certificate) string {
	if len(items) == 0 {
		return ""
	}
	keys := make([]string, 0, len(items))
	for _, item := range items {
		keys = append(keys, clusterSyncCertificateCacheKey(item))
	}
	slices.Sort(keys)
	return strings.Join(keys, "\n")
}

func isCertificateMaterialUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, certmgr.ErrMaterialUnavailable) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "material is not available")
}

func buildMirroredCertificates(
	remoteCertificates []certmgr.Certificate,
	previousCache map[string]clusterSyncCertificateCacheEntry,
	fetchBundle func(id string) ([]byte, error),
) ([]certmgr.MirroredCertificate, map[string]clusterSyncCertificateCacheEntry, string, error) {
	if previousCache == nil {
		previousCache = map[string]clusterSyncCertificateCacheEntry{}
	}
	mirrored := make([]certmgr.MirroredCertificate, 0, len(remoteCertificates))
	nextCache := make(map[string]clusterSyncCertificateCacheEntry, len(remoteCertificates))

	for _, remoteCertificate := range remoteCertificates {
		id := strings.TrimSpace(remoteCertificate.ID)
		if id == "" {
			return nil, nil, "", fmt.Errorf("remote certificate id is required")
		}
		cacheKey := clusterSyncCertificateCacheKey(remoteCertificate)
		if cached, ok := previousCache[id]; ok && cached.cacheKey == cacheKey {
			item := certmgr.MirroredCertificate{Certificate: remoteCertificate}
			if !cached.materialUnavailable && len(cached.bundleZIP) > 0 {
				item.BundleZIP = append([]byte(nil), cached.bundleZIP...)
			}
			mirrored = append(mirrored, item)
			nextCache[id] = cached
			continue
		}
		bundle, err := fetchBundle(id)
		if err != nil {
			if isCertificateMaterialUnavailable(err) {
				mirrored = append(mirrored, certmgr.MirroredCertificate{
					Certificate: remoteCertificate,
				})
				nextCache[id] = clusterSyncCertificateCacheEntry{
					cacheKey:            cacheKey,
					materialUnavailable: true,
				}
				continue
			}
			return nil, nil, "", err
		}
		cachedBundle := append([]byte(nil), bundle...)
		mirrored = append(mirrored, certmgr.MirroredCertificate{
			Certificate: remoteCertificate,
			BundleZIP:   cachedBundle,
		})
		nextCache[id] = clusterSyncCertificateCacheEntry{
			cacheKey:  cacheKey,
			bundleZIP: cachedBundle,
		}
	}

	return mirrored, nextCache, clusterSyncCertificateSetDigest(remoteCertificates), nil
}

func startClusterSync(cfg config.Config, siteStore *store.Store, nodeStore *node.Store, settingsStore *settings.Store, certManager *certmgr.Manager, applySettingsRuntime func(settings.Settings) error, runtimeState *clustersync.RuntimeState) {
	client, err := clustersync.New(clustersync.Config{
		BaseURL:  cfg.ClusterSyncURL,
		BaseURLs: cfg.ClusterSyncURLs,
		Username: cfg.ClusterSyncUsername,
		Password: cfg.ClusterSyncPassword,
		Timeout:  10 * time.Second,
	})
	if err != nil {
		log.Fatalf("cluster sync init failed: %v", err)
	}

	go func() {
		loopState := newClusterSyncLoopState()
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		consecutiveFailures := 0
		timer := time.NewTimer(0)
		defer timer.Stop()
		for {
			<-timer.C
			if err := runClusterSyncOnce(client, cfg, siteStore, nodeStore, settingsStore, certManager, applySettingsRuntime, runtimeState, loopState); err != nil {
				consecutiveFailures++
				log.Printf("cluster sync failed: %v", err)
			} else {
				consecutiveFailures = 0
			}
			timer.Reset(nextClusterSyncDelay(cfg.ClusterSyncInterval, consecutiveFailures, rng.Float64()))
		}
	}()
}

func configClusterSyncURLs(primary string, list []string) []string {
	items := make([]string, 0, 1+len(list))
	seen := map[string]struct{}{}
	for _, raw := range append([]string{primary}, list...) {
		value := strings.TrimRight(strings.TrimSpace(raw), "/")
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		items = append(items, value)
	}
	return items
}

func runClusterSyncOnce(client *clustersync.Client, cfg config.Config, siteStore *store.Store, nodeStore *node.Store, settingsStore *settings.Store, certManager *certmgr.Manager, applySettingsRuntime func(settings.Settings) error, runtimeState *clustersync.RuntimeState, loopState *clusterSyncLoopState) error {
	if loopState == nil {
		loopState = newClusterSyncLoopState()
	}
	now := time.Now().UTC()
	if runtimeState != nil {
		runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
		runtimeState.StartAttempt(now)
	}

	if err := client.UpsertNode(node.Node{
		ID:       cfg.NodeID,
		Name:     cfg.NodeName,
		Endpoint: cfg.AdminAddr,
		Enabled:  true,
	}); err != nil {
		if runtimeState != nil {
			runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
			runtimeState.MarkFailure("fetch_upsert_node", err, time.Now().UTC())
		}
		return err
	}
	if err := client.Heartbeat(cfg.NodeID); err != nil {
		if runtimeState != nil {
			runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
			runtimeState.MarkFailure("fetch_heartbeat", err, time.Now().UTC())
		}
		return err
	}
	nodes, err := client.FetchNodes()
	if err != nil {
		if runtimeState != nil {
			runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
			runtimeState.MarkFailure("fetch_nodes", err, time.Now().UTC())
		}
		return err
	}
	sites, err := client.FetchSites()
	if err != nil {
		if runtimeState != nil {
			runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
			runtimeState.MarkFailure("fetch_sites", err, time.Now().UTC())
		}
		return err
	}
	remoteSettings, err := client.FetchSettings()
	if err != nil {
		if runtimeState != nil {
			runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
			runtimeState.MarkFailure("fetch_settings", err, time.Now().UTC())
		}
		return err
	}
	if err := validateFollowerSyncedSettings(remoteSettings); err != nil {
		if runtimeState != nil {
			runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
			runtimeState.MarkFailure("validate_settings", err, time.Now().UTC())
		}
		return err
	}

	mirrorEnabled := remoteSettings.ClusterSync.CertificateSyncEnabled
	mirrored := make([]certmgr.MirroredCertificate, 0)
	certificateSetDigest := ""
	if mirrorEnabled && certManager != nil {
		remoteCertificates, err := client.FetchCertificates()
		if err != nil {
			if runtimeState != nil {
				runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
				runtimeState.MarkCertificateSyncFailure(err, time.Now().UTC())
				runtimeState.MarkFailure("fetch_certificates", err, time.Now().UTC())
			}
			return err
		}
		var nextCertificateCache map[string]clusterSyncCertificateCacheEntry
		var digest string
		mirrored, nextCertificateCache, digest, err = buildMirroredCertificates(remoteCertificates, loopState.certificateCache, client.FetchCertificateBundle)
		if err != nil {
			if runtimeState != nil {
				runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
				runtimeState.MarkCertificateSyncFailure(err, time.Now().UTC())
				runtimeState.MarkFailure("fetch_certificate_bundle", err, time.Now().UTC())
			}
			return err
		}
		loopState.certificateCache = nextCertificateCache
		certificateSetDigest = digest
	}
	if runtimeState != nil {
		runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
		runtimeState.MarkFetchSuccess(time.Now().UTC())
	}

	if err := nodeStore.ReplaceAll(nodes); err != nil {
		if runtimeState != nil {
			runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
			runtimeState.MarkFailure("apply_nodes", err, time.Now().UTC())
		}
		return err
	}
	if err := siteStore.ReplaceAll(sites); err != nil {
		if runtimeState != nil {
			runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
			runtimeState.MarkFailure("apply_sites", err, time.Now().UTC())
		}
		return err
	}

	if mirrorEnabled && certManager != nil {
		if loopState.appliedCertificateSetDigest != certificateSetDigest {
			if err := certManager.ReplaceMirrored(mirrored); err != nil {
				if runtimeState != nil {
					runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
					runtimeState.MarkCertificateSyncFailure(err, time.Now().UTC())
					runtimeState.MarkFailure("apply_certificates", err, time.Now().UTC())
				}
				return err
			}
			loopState.appliedCertificateSetDigest = certificateSetDigest
		}
		if runtimeState != nil {
			runtimeState.MarkCertificateSyncSuccess(len(mirrored), time.Now().UTC())
		}
	} else if runtimeState != nil {
		runtimeState.MarkCertificateSyncSuccess(0, time.Now().UTC())
	}

	mergedSettings := mergeClusterSyncedSettings(settingsStore.Get(), remoteSettings)
	updatedSettings, err := settingsStore.Update(mergedSettings)
	if err != nil {
		if runtimeState != nil {
			runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
			runtimeState.MarkFailure("apply_settings", err, time.Now().UTC())
		}
		return err
	}
	if applySettingsRuntime != nil {
		if err := applySettingsRuntime(updatedSettings); err != nil {
			if runtimeState != nil {
				runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
				runtimeState.MarkFailure("apply_settings_runtime", err, time.Now().UTC())
			}
			return err
		}
	}
	if runtimeState != nil {
		runtimeState.SetActiveEndpoint(client.ActiveEndpoint())
		runtimeState.MarkApplySuccess(time.Now().UTC())
		runtimeState.MarkSuccess(time.Now().UTC())
	}
	return nil
}

func mergeClusterSyncedSettings(local settings.Settings, remote settings.Settings) settings.Settings {
	merged := local
	merged.Language = remote.Language
	merged.WebAccess = remote.WebAccess
	merged.IPRuleSourceOrder = append([]string{}, remote.IPRuleSourceOrder...)
	merged.IPRuleSets = append([]settings.IPRuleSet{}, remote.IPRuleSets...)
	merged.IPCountryAutoUpdates = append([]settings.IPCountryAutoUpdate{}, remote.IPCountryAutoUpdates...)
	merged.ClusterSync = remote.ClusterSync
	merged.Backup = remote.Backup
	merged.Alert = remote.Alert
	merged.AdminTLS = remote.AdminTLS
	return merged
}

func applyDeclarativeDataToStores(fileCfg *config.FileConfig, siteStore *store.Store, settingsStore *settings.Store, certManager *certmgr.Manager) error {
	if fileCfg == nil {
		return nil
	}
	if settingsStore != nil && fileCfg.Settings != nil {
		if _, err := settingsStore.Update(*fileCfg.Settings); err != nil {
			return fmt.Errorf("settings apply failed: %w", err)
		}
	}
	if siteStore != nil && fileCfg.Sites != nil {
		if err := siteStore.ReplaceAll(*fileCfg.Sites); err != nil {
			return fmt.Errorf("sites apply failed: %w", err)
		}
	}
	if certManager != nil && fileCfg.Certificates != nil {
		if err := certManager.ReplaceAll(*fileCfg.Certificates); err != nil {
			return fmt.Errorf("certificates apply failed: %w", err)
		}
	}
	return nil
}

func validateFollowerSyncedSettings(value settings.Settings) error {
	if !value.AdminTLS.Enabled {
		return nil
	}
	if strings.TrimSpace(value.AdminTLS.CertFile) != "" || strings.TrimSpace(value.AdminTLS.KeyFile) != "" {
		return fmt.Errorf("cluster follower requires adminTls.certificateId and does not support adminTls.certFile/keyFile")
	}
	return nil
}

func clusterSyncFailCloseMiddleware(runtimeState *clustersync.RuntimeState, next http.Handler) http.Handler {
	if runtimeState == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		active, retryAfter := runtimeState.FailCloseStatus(time.Now().UTC())
		if active {
			if retryAfter > 0 {
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			}
			http.Error(w, "cluster sync fail-close active", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func buildHAMetrics(syncStatus clustersync.RuntimeStatus, controlWritable bool, electionMode string, leaderNodeID string, leaderSwitchCount uint64, localNodeID string, leaderFlapping bool, leaderRecentEventCount int) string {
	b := strings.Builder{}
	b.WriteString("# HELP flowproxy_control_writable Whether control-plane writes are allowed on this node (1=yes, 0=no)\n")
	b.WriteString("# TYPE flowproxy_control_writable gauge\n")
	if controlWritable {
		b.WriteString("flowproxy_control_writable 1\n")
	} else {
		b.WriteString("flowproxy_control_writable 0\n")
	}
	b.WriteString("# HELP flowproxy_ha_leader_switch_total Number of observed HA leader events on this node\n")
	b.WriteString("# TYPE flowproxy_ha_leader_switch_total counter\n")
	b.WriteString(fmt.Sprintf("flowproxy_ha_leader_switch_total %d\n", leaderSwitchCount))
	b.WriteString("# HELP flowproxy_ha_leader_flapping Whether leader changes are flapping recently (1=yes, 0=no)\n")
	b.WriteString("# TYPE flowproxy_ha_leader_flapping gauge\n")
	if leaderFlapping {
		b.WriteString("flowproxy_ha_leader_flapping 1\n")
	} else {
		b.WriteString("flowproxy_ha_leader_flapping 0\n")
	}
	b.WriteString("# HELP flowproxy_ha_leader_recent_events Number of leader events seen in recent flapping window\n")
	b.WriteString("# TYPE flowproxy_ha_leader_recent_events gauge\n")
	b.WriteString(fmt.Sprintf("flowproxy_ha_leader_recent_events %d\n", leaderRecentEventCount))
	b.WriteString("# HELP flowproxy_cluster_sync_fail_close_active Whether cluster-sync fail-close is active (1=yes, 0=no)\n")
	b.WriteString("# TYPE flowproxy_cluster_sync_fail_close_active gauge\n")
	if syncStatus.FailCloseActive {
		b.WriteString("flowproxy_cluster_sync_fail_close_active 1\n")
	} else {
		b.WriteString("flowproxy_cluster_sync_fail_close_active 0\n")
	}
	b.WriteString("# HELP flowproxy_cluster_sync_consecutive_failures Current consecutive cluster-sync failures\n")
	b.WriteString("# TYPE flowproxy_cluster_sync_consecutive_failures gauge\n")
	b.WriteString(fmt.Sprintf("flowproxy_cluster_sync_consecutive_failures %d\n", syncStatus.ConsecutiveFailures))
	b.WriteString("# HELP flowproxy_cluster_sync_last_success_timestamp_seconds Last successful cluster-sync unix timestamp\n")
	b.WriteString("# TYPE flowproxy_cluster_sync_last_success_timestamp_seconds gauge\n")
	if syncStatus.LastSuccessAt.IsZero() {
		b.WriteString("flowproxy_cluster_sync_last_success_timestamp_seconds 0\n")
	} else {
		b.WriteString(fmt.Sprintf("flowproxy_cluster_sync_last_success_timestamp_seconds %d\n", syncStatus.LastSuccessAt.Unix()))
	}
	b.WriteString("# HELP flowproxy_ha_leader_is_local Whether current leader is local node (1=yes, 0=no)\n")
	b.WriteString("# TYPE flowproxy_ha_leader_is_local gauge\n")
	if strings.TrimSpace(leaderNodeID) != "" && node.NormalizeID(leaderNodeID) == node.NormalizeID(localNodeID) {
		b.WriteString("flowproxy_ha_leader_is_local 1\n")
	} else {
		b.WriteString("flowproxy_ha_leader_is_local 0\n")
	}
	b.WriteString("# HELP flowproxy_ha_leader_info Leader identity and election mode (always 1)\n")
	b.WriteString("# TYPE flowproxy_ha_leader_info gauge\n")
	b.WriteString(fmt.Sprintf("flowproxy_ha_leader_info{leader_node_id=\"%s\",election_mode=\"%s\",local_node_id=\"%s\"} 1\n",
		prometheusLabelEscape(strings.TrimSpace(leaderNodeID)),
		prometheusLabelEscape(strings.TrimSpace(electionMode)),
		prometheusLabelEscape(strings.TrimSpace(localNodeID)),
	))
	return b.String()
}

func prometheusLabelEscape(value string) string {
	value = strings.ReplaceAll(value, `\\`, `\\\\`)
	value = strings.ReplaceAll(value, `"`, `\\"`)
	value = strings.ReplaceAll(value, "\n", `\\n`)
	return value
}
