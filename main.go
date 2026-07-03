package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	StatusPending = "pending"
	StatusRunning = "running"
	StatusDone    = "completed"
	StatusTimeout = "timeout"

	DefaultTimeoutSeconds = 600
)

type Config struct {
	Addr                   string `json:"addr"`
	DBPath                 string `json:"db_path"`
	POCDir                 string `json:"poc_dir"`
	FscanPath              string `json:"fscan_path"`
	FscanThreads           int    `json:"fscan_threads"`
	FscanTimeout           int    `json:"fscan_timeout"`
	FscanPorts             []int  `json:"fscan_ports"`
	POCMap                 string `json:"poc_map"`
	Workers                int    `json:"workers"`
	NucleiConcurrency      int    `json:"nuclei_concurrency"`
	NucleiHostConcurrency  int    `json:"nuclei_host_concurrency"`
	NucleiTimeout          int    `json:"nuclei_timeout"`
	HTTPFingerprintTimeout int    `json:"http_fingerprint_timeout"`
}

type scanRequest struct {
	Namespace string   `json:"namespace"`
	IPHosts   []string `json:"ip_hosts"`
	Timeout   int      `json:"timeout"`
}

type scanJob struct {
	Namespace string
	IP        string
}

type app struct {
	cfg    Config
	store  *Store
	jobs   chan scanJob
	ctx    context.Context
	cancel context.CancelFunc

	queuedMu sync.Mutex
	queued   map[string]struct{}

	activeMu sync.Mutex
	active   map[string]context.CancelFunc
}

func main() {
	if code, ok := runHelp(os.Args[1:]); ok {
		os.Exit(code)
	}
	if code, ok := runScanChild(os.Args[1:]); ok {
		os.Exit(code)
	}
	if code, ok := runScanCLI(os.Args[1:]); ok {
		os.Exit(code)
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	store, err := OpenStore(cfg.DBPath)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	if err := store.ResetRunning(context.Background()); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := &app{
		cfg:    cfg,
		store:  store,
		jobs:   make(chan scanJob, cfg.Workers),
		queued: make(map[string]struct{}),
		active: make(map[string]context.CancelFunc),
	}
	a.ctx, a.cancel = context.WithCancel(ctx)
	defer a.cancel()

	a.startWorkers()
	go forever(a.ctx, time.Second, "dispatch", a.dispatchPending)
	go forever(a.ctx, time.Minute, "timeout", a.enforceTimeouts)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           localOnly(a.routes()),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-a.ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("listening on http://%s poc_dir=%s fscan=%s workers=%d", cfg.Addr, cfg.POCDir, cfg.FscanPath, cfg.Workers)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func loadConfig() (Config, error) {
	cfg := Config{
		Addr:                   "127.0.0.1:8080",
		DBPath:                 "tasks.db",
		POCDir:                 filepath.Join(executableDir(), "poc"),
		FscanPath:              "fscan",
		FscanThreads:           256,
		FscanTimeout:           3,
		Workers:                int(math.Ceil(float64(runtime.NumCPU()) * 1.5)),
		NucleiConcurrency:      25,
		NucleiHostConcurrency:  1,
		NucleiTimeout:          5,
		HTTPFingerprintTimeout: 2,
	}
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}

	configPath := firstEnv("VST_CONFIG", "CONFIG")
	if configPath != "" {
		b, err := os.ReadFile(configPath)
		if err != nil {
			return cfg, err
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cfg, err
		}
	}

	applyStringEnv(&cfg.Addr, "VST_ADDR", "ADDR")
	applyStringEnv(&cfg.DBPath, "VST_DB", "DB_PATH")
	applyStringEnv(&cfg.POCDir, "VST_POC_DIR", "POC_DIR")
	applyStringEnv(&cfg.FscanPath, "VST_FSCAN_PATH", "FSCAN_PATH")
	applyIntEnv(&cfg.FscanThreads, "VST_FSCAN_THREADS", "FSCAN_THREADS")
	applyIntEnv(&cfg.FscanTimeout, "VST_FSCAN_TIMEOUT", "FSCAN_TIMEOUT")
	applyPortsEnv(&cfg.FscanPorts, "VST_FSCAN_PORTS", "FSCAN_PORTS")
	applyStringEnv(&cfg.POCMap, "VST_POC_MAP", "POC_MAP")
	applyIntEnv(&cfg.Workers, "VST_WORKERS", "WORKERS")
	applyIntEnv(&cfg.NucleiConcurrency, "VST_NUCLEI_CONCURRENCY", "NUCLEI_CONCURRENCY")
	applyIntEnv(&cfg.NucleiHostConcurrency, "VST_NUCLEI_HOST_CONCURRENCY", "NUCLEI_HOST_CONCURRENCY")
	applyIntEnv(&cfg.NucleiTimeout, "VST_NUCLEI_TIMEOUT", "NUCLEI_TIMEOUT")
	applyIntEnv(&cfg.HTTPFingerprintTimeout, "VST_HTTP_FINGERPRINT_TIMEOUT", "HTTP_FINGERPRINT_TIMEOUT")

	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8080"
	}
	if cfg.DBPath == "" {
		cfg.DBPath = "tasks.db"
	}
	if cfg.POCDir == "" {
		cfg.POCDir = filepath.Join(executableDir(), "poc")
	}
	if cfg.FscanPath == "" {
		cfg.FscanPath = "fscan"
	}
	if cfg.FscanThreads < 1 {
		cfg.FscanThreads = 256
	}
	if cfg.FscanTimeout < 1 {
		cfg.FscanTimeout = 3
	}
	if cfg.Workers < 1 {
		cfg.Workers = 1
	}
	if cfg.NucleiConcurrency < 1 {
		cfg.NucleiConcurrency = 25
	}
	if cfg.NucleiHostConcurrency < 1 {
		cfg.NucleiHostConcurrency = 1
	}
	if cfg.NucleiTimeout < 1 {
		cfg.NucleiTimeout = 5
	}
	if cfg.HTTPFingerprintTimeout < 0 {
		cfg.HTTPFingerprintTimeout = 0
	}
	return cfg, nil
}

func executableDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func applyStringEnv(dst *string, keys ...string) {
	if value := firstEnv(keys...); value != "" {
		*dst = value
	}
}

func applyIntEnv(dst *int, keys ...string) {
	value := firstEnv(keys...)
	if value == "" {
		return
	}
	n, err := strconv.Atoi(value)
	if err == nil {
		*dst = n
	}
}

func applyPortsEnv(dst *[]int, keys ...string) {
	value := firstEnv(keys...)
	if value == "" {
		return
	}
	ports, err := parsePortList(value)
	if err == nil {
		*dst = ports
	}
}

func parsePortList(value string) ([]int, error) {
	seen := map[int]struct{}{}
	var ports []int
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		port, err := strconv.Atoi(part)
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("invalid port list")
		}
		if _, ok := seen[port]; ok {
			continue
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	slices.Sort(ports)
	return ports, nil
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			a.handlePostScan(w, r)
		case http.MethodGet:
			namespace := strings.TrimSpace(r.URL.Query().Get("namespace"))
			if namespace == "" {
				writeError(w, http.StatusBadRequest, "missing namespace")
				return
			}
			a.handleGetScan(w, r, namespace)
		default:
			w.Header().Set("Allow", "GET, POST")
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
	mux.HandleFunc("/scan/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		namespace := strings.Trim(strings.TrimPrefix(r.URL.Path, "/scan/"), "/")
		if namespace == "" {
			writeError(w, http.StatusBadRequest, "missing namespace")
			return
		}
		a.handleGetScan(w, r, namespace)
	})
	return mux
}

func (a *app) handlePostScan(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var raw json.RawMessage
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20))
	if err := dec.Decode(&raw); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	requests, batch, err := parseScanRequests(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	results := make([]UpsertResult, 0, len(requests))
	for _, req := range requests {
		result, err := a.upsertScanRequest(r.Context(), req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		results = append(results, result)
	}
	if batch {
		writeJSON(w, http.StatusOK, results)
		return
	}
	writeJSON(w, http.StatusOK, results[0])
}

func parseScanRequests(raw json.RawMessage) ([]scanRequest, bool, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, false, errors.New("empty request body")
	}

	switch raw[0] {
	case '{':
		var req scanRequest
		if err := decodeJSON(raw, &req); err != nil {
			return nil, false, err
		}
		return []scanRequest{req}, false, nil
	case '[':
		var requests []scanRequest
		if err := decodeJSON(raw, &requests); err != nil {
			return nil, false, err
		}
		if len(requests) == 0 {
			return nil, true, errors.New("empty scan request list")
		}
		return requests, true, nil
	}
	return nil, false, errors.New("scan request must be an object or array")
}

func decodeJSON(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func (a *app) upsertScanRequest(ctx context.Context, req scanRequest) (UpsertResult, error) {
	namespace := strings.TrimSpace(req.Namespace)
	hosts := normalizeHosts(req.IPHosts)
	if !validNamespace(namespace) {
		return UpsertResult{}, errors.New("namespace is required")
	}
	if len(hosts) == 0 {
		return UpsertResult{}, errors.New("ip_hosts is required")
	}
	if req.Timeout <= 0 {
		req.Timeout = DefaultTimeoutSeconds
	}

	result, err := a.store.UpsertTask(ctx, namespace, hosts, req.Timeout)
	if err != nil {
		return result, err
	}
	a.cancelRemoved(namespace, result.Removed)
	return result, nil
}

func validNamespace(namespace string) bool {
	return namespace != "" && namespace != "." && namespace != ".." && !strings.ContainsAny(namespace, "/\x00")
}

func normalizeHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	slices.Sort(out)
	return out
}

func (a *app) handleGetScan(w http.ResponseWriter, r *http.Request, namespace string) {
	result, err := a.store.GetTask(r.Context(), namespace)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, "namespace not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (a *app) startWorkers() {
	for i := 0; i < a.cfg.Workers; i++ {
		go a.worker()
	}
}

func (a *app) worker() {
	for job := range a.jobs {
		a.unqueue(job)
		timeout, ok, err := a.store.BeginHost(a.ctx, job.Namespace, job.IP)
		if err != nil {
			log.Printf("begin host %s/%s: %v", job.Namespace, job.IP, err)
			continue
		}
		if !ok {
			continue
		}

		scanCtx, cancel := context.WithTimeout(a.ctx, time.Duration(timeout)*time.Second)
		a.activate(job, cancel)
		scanResult, scanErr := a.scanHost(scanCtx, job.Namespace, job.IP)
		a.deactivate(job)
		cancel()

		if errors.Is(scanCtx.Err(), context.DeadlineExceeded) {
			if err := a.store.TimeoutHost(context.Background(), job.Namespace, job.IP); err != nil {
				log.Printf("timeout host %s/%s: %v", job.Namespace, job.IP, err)
			}
			continue
		}
		if scanCtx.Err() != nil {
			continue
		}
		if err := a.store.CompleteHost(context.Background(), job.Namespace, job.IP, scanResult.VulnerabilityIDs, scanResult.Assets, scanErr); err != nil {
			log.Printf("complete host %s/%s: %v", job.Namespace, job.IP, err)
		}
	}
}

func (a *app) dispatchPending(ctx context.Context) {
	pending, err := a.store.PendingHosts(ctx)
	if err != nil {
		log.Printf("load pending hosts: %v", err)
		return
	}
	for _, job := range pending {
		if !a.tryQueue(job) {
			return
		}
	}
}

func (a *app) tryQueue(job scanJob) bool {
	key := jobKey(job.Namespace, job.IP)
	a.queuedMu.Lock()
	if _, ok := a.queued[key]; ok {
		a.queuedMu.Unlock()
		return true
	}
	a.queued[key] = struct{}{}
	a.queuedMu.Unlock()

	select {
	case a.jobs <- job:
		return true
	default:
		a.queuedMu.Lock()
		delete(a.queued, key)
		a.queuedMu.Unlock()
		return false
	}
}

func (a *app) unqueue(job scanJob) {
	a.queuedMu.Lock()
	delete(a.queued, jobKey(job.Namespace, job.IP))
	a.queuedMu.Unlock()
}

func (a *app) activate(job scanJob, cancel context.CancelFunc) {
	a.activeMu.Lock()
	a.active[jobKey(job.Namespace, job.IP)] = cancel
	a.activeMu.Unlock()
}

func (a *app) deactivate(job scanJob) {
	a.activeMu.Lock()
	delete(a.active, jobKey(job.Namespace, job.IP))
	a.activeMu.Unlock()
}

func (a *app) cancelRemoved(namespace string, hosts []string) {
	for _, host := range hosts {
		job := scanJob{Namespace: namespace, IP: host}
		a.unqueue(job)
		a.cancelJob(job)
	}
}

func (a *app) cancelJob(job scanJob) {
	a.activeMu.Lock()
	cancel := a.active[jobKey(job.Namespace, job.IP)]
	a.activeMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (a *app) enforceTimeouts(ctx context.Context) {
	overdue, err := a.store.OverdueHosts(ctx, time.Now().UTC())
	if err != nil {
		log.Printf("load overdue hosts: %v", err)
		return
	}
	for _, job := range overdue {
		a.cancelJob(job)
		if err := a.store.TimeoutHost(ctx, job.Namespace, job.IP); err != nil {
			log.Printf("mark timeout %s/%s: %v", job.Namespace, job.IP, err)
		}
	}
}

func jobKey(namespace, ip string) string {
	return namespace + "\x00" + ip
}

func forever(ctx context.Context, interval time.Duration, name string, fn func(context.Context)) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("%s loop recovered: %v", name, r)
					}
				}()
				fn(ctx)
			}()
			timer.Reset(interval)
		}
	}
}

func localOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			writeError(w, http.StatusForbidden, "local requests only")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
