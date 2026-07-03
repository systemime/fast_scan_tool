package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	fscan "github.com/shadow1ng/fscan/pkg/fscan"
)

const scanChildCommand = "__scan_host"

type hostScanResult struct {
	VulnerabilityIDs []string `json:"vulnerability_ids,omitempty"`
	Assets           []Asset  `json:"assets,omitempty"`
}

type scanChildResult struct {
	VulnerabilityIDs []string `json:"vulnerability_ids,omitempty"`
	Assets           []Asset  `json:"assets,omitempty"`
	Error            string   `json:"error,omitempty"`
}

type cliScanResult struct {
	Namespace string          `json:"namespace"`
	Hosts     []cliHostResult `json:"hosts"`
}

type cliHostResult struct {
	IP               string   `json:"ip"`
	Assets           []Asset  `json:"assets"`
	Vulnerabilities  int      `json:"vulnerabilities"`
	VulnerabilityIDs []string `json:"vulnerability_ids"`
	Error            string   `json:"error,omitempty"`
}

func runHelp(args []string) (int, bool) {
	if len(args) == 0 {
		return 0, false
	}
	if args[0] != "-h" && args[0] != "--help" && args[0] != "help" {
		return 0, false
	}
	fmt.Fprint(os.Stdout, `Usage:
  vulnscan-wrapper                 start HTTP service
  vulnscan-wrapper scan [flags]    scan namespace IPs and write JSON

Run "vulnscan-wrapper scan -h" for scan flags.
`)
	return 0, true
}

func runScanCLI(args []string) (int, bool) {
	if len(args) == 0 || args[0] != "scan" {
		return 0, false
	}

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	namespace := fs.String("namespace", "", "Linux network namespace")
	ips := fs.String("ips", "", "comma-separated IP/host list")
	out := fs.String("out", "scan-result.json", "output JSON file")
	timeout := fs.Int("timeout", DefaultTimeoutSeconds, "per-host timeout seconds")
	workers := fs.Int("workers", 6, "parallel host scans")
	totalTimeout := fs.Int("total-timeout", 1800, "total scan timeout seconds, 0 disables")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, true
		}
		log.Print(err)
		return 2, true
	}

	req := scanRequest{Namespace: *namespace, IPHosts: strings.Split(*ips, ","), Timeout: *timeout}
	if !validNamespace(strings.TrimSpace(req.Namespace)) {
		log.Print("namespace is required")
		return 2, true
	}
	hosts := normalizeHosts(req.IPHosts)
	if len(hosts) == 0 {
		log.Print("ips is required")
		return 2, true
	}
	if strings.TrimSpace(*out) == "" {
		log.Print("out is required")
		return 2, true
	}
	if req.Timeout <= 0 {
		req.Timeout = DefaultTimeoutSeconds
	}
	if *workers < 1 {
		*workers = 1
	}
	if *workers > len(hosts) {
		*workers = len(hosts)
	}

	cfg, err := loadConfig()
	if err != nil {
		log.Print(err)
		return 1, true
	}
	a := &app{cfg: cfg}
	result := cliScanResult{Namespace: strings.TrimSpace(req.Namespace)}
	ctx := context.Background()
	cancel := func() {}
	if *totalTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(*totalTimeout)*time.Second)
	}
	result.Hosts = scanCLIHosts(ctx, result.Namespace, hosts, req.Timeout, *workers, a.scanHost)
	cancel()

	if err := ctx.Err(); err != nil {
		log.Print(err)
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Print(err)
		return 1, true
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0644); err != nil {
		log.Print(err)
		return 1, true
	}
	return 0, true
}

type scanHostFunc func(context.Context, string, string) (hostScanResult, error)

func scanCLIHosts(ctx context.Context, namespace string, hosts []string, timeout, workers int, scan scanHostFunc) []cliHostResult {
	if workers < 1 {
		workers = 1
	}
	if workers > len(hosts) {
		workers = len(hosts)
	}
	results := make([]cliHostResult, len(hosts))
	type job struct {
		index int
		ip    string
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				results[job.index] = scanCLIHost(ctx, namespace, job.ip, timeout, scan)
			}
		}()
	}
submitJobs:
	for index, ip := range hosts {
		if err := ctx.Err(); err != nil {
			for i := index; i < len(hosts); i++ {
				results[i] = cliHostResult{IP: hosts[i], Error: err.Error()}
			}
			break
		}
		select {
		case jobs <- job{index: index, ip: ip}:
		case <-ctx.Done():
			err := ctx.Err()
			for i := index; i < len(hosts); i++ {
				results[i] = cliHostResult{IP: hosts[i], Error: err.Error()}
			}
			break submitJobs
		}
	}
	close(jobs)
	wg.Wait()
	return results
}

func scanCLIHost(ctx context.Context, namespace, ip string, timeout int, scan scanHostFunc) cliHostResult {
	host := cliHostResult{IP: ip}
	if err := ctx.Err(); err != nil {
		host.Error = err.Error()
		return host
	}
	hostCtx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	scanResult, scanErr := scan(hostCtx, namespace, ip)
	cancel()
	host.Assets = scanResult.Assets
	host.VulnerabilityIDs = uniqueSorted(scanResult.VulnerabilityIDs)
	host.Vulnerabilities = len(host.VulnerabilityIDs)
	if scanErr != nil {
		host.Error = scanErr.Error()
	}
	return host
}

func runScanChild(args []string) (int, bool) {
	if len(args) == 0 || args[0] != scanChildCommand {
		return 0, false
	}

	fs := flag.NewFlagSet(scanChildCommand, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pocDir := fs.String("poc-dir", "", "")
	fscanPath := fs.String("fscan-path", "fscan", "")
	fscanThreads := fs.Int("fscan-threads", 256, "")
	fscanTimeout := fs.Int("fscan-timeout", 3, "")
	fscanPorts := fs.String("fscan-ports", "", "")
	pocMap := fs.String("poc-map", "", "")
	concurrency := fs.Int("nuclei-concurrency", 25, "")
	hostConcurrency := fs.Int("nuclei-host-concurrency", 1, "")
	nucleiTimeout := fs.Int("nuclei-timeout", 5, "")
	httpFingerprintTimeout := fs.Int("http-fingerprint-timeout", 2, "")
	target := fs.String("target", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return writeScanChildResult(hostScanResult{}, err)
	}
	if *pocDir == "" || *target == "" {
		return writeScanChildResult(hostScanResult{}, errors.New("poc-dir and target are required"))
	}

	result, err := scanDirect(context.Background(), Config{
		POCDir:                 *pocDir,
		FscanPath:              *fscanPath,
		FscanThreads:           *fscanThreads,
		FscanTimeout:           *fscanTimeout,
		FscanPorts:             mustParsePortList(*fscanPorts),
		POCMap:                 *pocMap,
		NucleiConcurrency:      *concurrency,
		NucleiHostConcurrency:  *hostConcurrency,
		NucleiTimeout:          *nucleiTimeout,
		HTTPFingerprintTimeout: *httpFingerprintTimeout,
	}, *target)
	return writeScanChildResult(result, err)
}

func writeScanChildResult(result hostScanResult, err error) (int, bool) {
	out := scanChildResult{VulnerabilityIDs: result.VulnerabilityIDs, Assets: result.Assets}
	if err != nil {
		out.Error = err.Error()
	}
	_ = json.NewEncoder(os.Stdout).Encode(out)
	return 0, true
}

func (a *app) scanHost(ctx context.Context, namespace, ip string) (hostScanResult, error) {
	if namespace != "" {
		if runtime.GOOS != "linux" {
			return hostScanResult{}, fmt.Errorf("network namespace %q requires linux", namespace)
		}
		return a.scanHostProcess(ctx, namespace, ip)
	}
	return scanDirect(ctx, a.cfg, ip)
}

func (a *app) scanHostProcess(ctx context.Context, namespace, ip string) (hostScanResult, error) {
	exe, err := os.Executable()
	if err != nil {
		return hostScanResult{}, err
	}

	cmd := exec.Command("ip", "netns", "exec", namespace, exe, scanChildCommand,
		"-poc-dir", a.cfg.POCDir,
		"-fscan-path", a.cfg.FscanPath,
		"-fscan-threads", strconv.Itoa(a.cfg.FscanThreads),
		"-fscan-timeout", strconv.Itoa(a.cfg.FscanTimeout),
		"-fscan-ports", formatPortList(a.cfg.FscanPorts),
		"-poc-map", a.cfg.POCMap,
		"-nuclei-concurrency", strconv.Itoa(a.cfg.NucleiConcurrency),
		"-nuclei-host-concurrency", strconv.Itoa(a.cfg.NucleiHostConcurrency),
		"-nuclei-timeout", strconv.Itoa(a.cfg.NucleiTimeout),
		"-http-fingerprint-timeout", strconv.Itoa(a.cfg.HTTPFingerprintTimeout),
		"-target", ip,
	)
	stdout, stderr, runErr := runProcess(ctx, cmd)
	if logText := strings.TrimSpace(string(stderr)); logText != "" {
		log.Print(logText)
	}
	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
		return hostScanResult{}, runErr
	}

	var result scanChildResult
	if len(stdout) > 0 {
		if err := json.Unmarshal(stdout, &result); err != nil {
			return hostScanResult{}, err
		}
		if result.Error != "" {
			return hostScanResult{VulnerabilityIDs: result.VulnerabilityIDs, Assets: result.Assets}, errors.New(result.Error)
		}
	}
	if runErr != nil {
		errText := strings.TrimSpace(string(stderr))
		if errText != "" {
			return hostScanResult{}, fmt.Errorf("%w: %s", runErr, errText)
		}
		return hostScanResult{}, runErr
	}
	return hostScanResult{VulnerabilityIDs: result.VulnerabilityIDs, Assets: result.Assets}, nil
}

func scanDirect(ctx context.Context, cfg Config, ip string) (hostScanResult, error) {
	assets, fscanErr := runFscan(ctx, cfg, ip)
	if ctx.Err() != nil {
		return hostScanResult{Assets: assets}, ctx.Err()
	}
	assets = enrichHTTPFingerprints(ctx, cfg, assets)
	if ctx.Err() != nil {
		return hostScanResult{Assets: assets}, ctx.Err()
	}

	selection := selectNucleiTemplatesWithStats(cfg.POCDir, cfg.POCMap, assets)
	logTemplateSelection(cfg.POCDir, selection)
	if selection.SkipNuclei {
		return hostScanResult{Assets: assets}, fscanErr
	}
	targetAssets := assets
	if len(selection.TargetAssets) > 0 {
		targetAssets = selection.TargetAssets
	}
	ids, nucleiErr := scanNucleiTargets(ctx, cfg, nucleiTargets(ip, targetAssets), selection.Templates)
	return hostScanResult{VulnerabilityIDs: ids, Assets: assets}, errors.Join(fscanErr, nucleiErr)
}

func runFscan(ctx context.Context, cfg Config, ip string) ([]Asset, error) {
	scanner := fscan.NewScanner(fscan.Config{
		Threads:        cfg.FscanThreads,
		Timeout:        time.Duration(cfg.FscanTimeout) * time.Second,
		Ports:          append([]int(nil), cfg.FscanPorts...),
		Plugins:        fscanDetectPlugins(),
		DisablePing:    true,
		DisableBrute:   true,
		DisablePOCScan: true,
	})
	var assets []Asset
	err := scanner.ScanEach(ctx, func(result fscan.Result) error {
		if asset := assetFromFscanResult(result); asset.Target != "" {
			assets = append(assets, asset)
		}
		return nil
	}, fscan.Target{Host: ip})
	return uniqueAssets(assets), err
}

func enrichHTTPFingerprints(ctx context.Context, cfg Config, assets []Asset) []Asset {
	if cfg.HTTPFingerprintTimeout <= 0 || len(assets) == 0 {
		return assets
	}
	out := append([]Asset(nil), assets...)
	client := &http.Client{
		Timeout:   time.Duration(cfg.HTTPFingerprintTimeout) * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for i := range out {
		if ctx.Err() != nil {
			return out
		}
		url := httpFingerprintURL(out[i])
		if url == "" {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "vulnscan-wrapper")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))
		_ = resp.Body.Close()

		values := httpFingerprintValues(resp.Header, body)
		if out[i].Server == "" {
			out[i].Server = resp.Header.Get("Server")
		}
		if out[i].Title == "" {
			out[i].Title = htmlTitle(body)
		}
		out[i].Fingerprints = uniqueSorted(append(out[i].Fingerprints, values...))
		out[i].IsWeb = true
	}
	return uniqueAssets(out)
}

func httpFingerprintURL(asset Asset) string {
	if asset.URL != "" && strings.Contains(asset.URL, "://") {
		return asset.URL
	}
	if !asset.IsWeb && asset.Service != "http" && asset.Service != "https" && asset.Protocol != "http" && asset.Protocol != "https" {
		return ""
	}
	return buildURL(asset)
}

func httpFingerprintValues(header http.Header, body []byte) []string {
	values := []string{
		header.Get("Server"),
		header.Get("X-Powered-By"),
		header.Get("WWW-Authenticate"),
		htmlTitle(body),
	}
	for _, cookie := range header.Values("Set-Cookie") {
		if name, _, ok := strings.Cut(cookie, "="); ok {
			values = append(values, "cookie:"+name)
		}
	}
	lower := strings.ToLower(string(body))
	for _, keyword := range []string{
		"spring", "thinkphp", "wordpress", "jenkins", "weblogic", "nacos",
		"elasticsearch", "elastic", "kibana", "wazuh", "nginx", "tomcat",
		"grafana", "prometheus", "gitlab", "harbor", "minio",
	} {
		if strings.Contains(lower, keyword) {
			values = append(values, keyword)
		}
	}
	return uniqueSorted(values)
}

func htmlTitle(body []byte) string {
	lower := strings.ToLower(string(body))
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	start = strings.Index(lower[start:], ">")
	if start < 0 {
		return ""
	}
	titleStart := strings.Index(lower, "<title") + start + 1
	end := strings.Index(lower[titleStart:], "</title>")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(html.UnescapeString(string(body[titleStart : titleStart+end])))
}

func fscanDetectPlugins() []string {
	var plugins []string
	for _, plugin := range fscan.ListPlugins() {
		if !plugin.Default || !plugin.Safe || !slices.Contains(plugin.Capabilities, fscan.PluginCapabilityDetect) {
			continue
		}
		if hasAnyFscanCapability(plugin.Capabilities,
			fscan.PluginCapabilityAuthCheck,
			fscan.PluginCapabilityBrute,
			fscan.PluginCapabilityPOC,
			fscan.PluginCapabilityLocalEffect,
		) {
			continue
		}
		plugins = append(plugins, plugin.Name)
	}
	slices.Sort(plugins)
	if len(plugins) == 0 {
		return []string{"webtitle"}
	}
	return plugins
}

func hasAnyFscanCapability(capabilities []string, forbidden ...string) bool {
	for _, capability := range forbidden {
		if slices.Contains(capabilities, capability) {
			return true
		}
	}
	return false
}

func mustParsePortList(value string) []int {
	ports, err := parsePortList(value)
	if err != nil {
		return nil
	}
	return ports
}

func formatPortList(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	out := make([]string, 0, len(ports))
	for _, port := range ports {
		out = append(out, strconv.Itoa(port))
	}
	return strings.Join(out, ",")
}

func runProcess(ctx context.Context, cmd *exec.Cmd) ([]byte, []byte, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return stdout.Bytes(), stderr.Bytes(), err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		return stdout.Bytes(), stderr.Bytes(), err
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return stdout.Bytes(), stderr.Bytes(), ctx.Err()
	}
}

func assetFromFscanResult(result fscan.Result) Asset {
	asset := Asset{
		Type:          strings.ToUpper(strings.TrimSpace(result.Type)),
		Target:        strings.TrimSpace(result.Target),
		Status:        strings.TrimSpace(result.Status),
		Port:          detailInt(result.Details, "port"),
		Service:       strings.ToLower(detailString(result.Details, "service")),
		Protocol:      strings.ToLower(detailString(result.Details, "protocol")),
		URL:           detailString(result.Details, "url"),
		Title:         detailString(result.Details, "title"),
		Server:        detailString(result.Details, "server"),
		Banner:        detailString(result.Details, "banner"),
		StatusCode:    firstInt(result.Details, "status", "status_code"),
		Fingerprints:  detailStrings(result.Details, "fingerprints"),
		Vulnerability: detailString(result.Details, "vulnerability"),
		IsWeb:         detailBool(result.Details, "is_web"),
	}
	if result.IsPort() {
		if port, ok := result.Port(); ok {
			asset.Port = port
		}
	}
	if service, ok := result.AsService(); ok {
		asset.Port = firstNonZero(asset.Port, service.Port)
		asset.Service = firstNonEmpty(asset.Service, strings.ToLower(service.Service))
		asset.Protocol = firstNonEmpty(asset.Protocol, strings.ToLower(service.Protocol))
		asset.URL = firstNonEmpty(asset.URL, service.URL)
		asset.Banner = firstNonEmpty(asset.Banner, service.Banner)
		asset.IsWeb = asset.IsWeb || service.IsWeb
		for _, value := range []string{service.Product, service.Version} {
			if strings.TrimSpace(value) != "" {
				asset.Fingerprints = append(asset.Fingerprints, value)
			}
		}
	}
	if strings.Contains(asset.Target, "://") && asset.URL == "" {
		asset.URL = asset.Target
	}
	if asset.IsWeb || asset.StatusCode != 0 || asset.Server != "" || asset.Title != "" || asset.Service == "http" || asset.Service == "https" || asset.Protocol == "http" || asset.Protocol == "https" {
		asset.IsWeb = true
		if asset.URL == "" {
			asset.URL = buildURL(asset)
		}
	}
	return asset
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func scanNucleiTargets(ctx context.Context, cfg Config, targets, templates []string) ([]string, error) {
	if len(templates) == 0 {
		templates = []string{cfg.POCDir}
	}
	ids := map[string]struct{}{}
	var idsMu sync.Mutex
	ne, err := nuclei.NewNucleiEngine(
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: templates}),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
		nuclei.WithNetworkConfig(nuclei.NetworkConfig{
			Timeout:      cfg.NucleiTimeout,
			Retries:      1,
			MaxHostError: 30,
		}),
		nuclei.WithConcurrency(nuclei.Concurrency{
			TemplateConcurrency:         cfg.NucleiConcurrency,
			HostConcurrency:             cfg.NucleiHostConcurrency,
			HeadlessHostConcurrency:     1,
			HeadlessTemplateConcurrency: 1,
		}),
	)
	if err != nil {
		return nil, err
	}
	defer ne.Close()

	ne.LoadTargets(targets, true)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	err = ne.ExecuteWithCallback(func(event *output.ResultEvent) {
		if event != nil && event.TemplateID != "" {
			idsMu.Lock()
			ids[event.TemplateID] = struct{}{}
			idsMu.Unlock()
		}
	})
	idsMu.Lock()
	defer idsMu.Unlock()
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	slices.Sort(out)
	return out, err
}

func selectNucleiTemplates(pocDir, mapPath string, assets []Asset) []string {
	return selectNucleiTemplatesWithStats(pocDir, mapPath, assets).Templates
}

type templateSelection struct {
	Templates       []string
	FingerprintHits []string
	Reasons         []string
	FallbackFull    bool
	MatchedAssets   int
	AssetCount      int
	TargetAssets    []Asset
	SkipNuclei      bool
}

func selectNucleiTemplatesWithStats(pocDir, mapPath string, assets []Asset) templateSelection {
	assetCount := len(assets)
	mapPath = strings.TrimSpace(mapPath)
	if mapPath == "" {
		return templateSelection{FallbackFull: true, AssetCount: assetCount}
	}
	data, err := os.ReadFile(mapPath)
	if err != nil {
		return templateSelection{FallbackFull: true, AssetCount: assetCount}
	}
	var mapping map[string][]string
	if err := json.Unmarshal(data, &mapping); err != nil {
		return templateSelection{FallbackFull: true, AssetCount: assetCount}
	}
	normalizedMapping := map[string][]string{}
	for key, values := range mapping {
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "" {
			normalizedMapping[key] = append(normalizedMapping[key], values...)
		}
	}

	matchedAssets := 0
	var targetAssets []Asset
	for _, asset := range assets {
		if len(matchPOCMapKeys(assetFingerprints([]Asset{asset}), normalizedMapping)) > 0 {
			matchedAssets++
			targetAssets = append(targetAssets, asset)
		}
	}

	fingerprints := assetFingerprints(assets)
	seen := map[string]struct{}{}
	hits := map[string]struct{}{}
	reasons := map[string]struct{}{}
	var out []string
	addTemplate := func(key, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		value = safeTemplatePath(pocDir, value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
		if key != "" {
			reasons[key+"=>"+value] = struct{}{}
		}
	}
	matched := false
	for key := range matchPOCMapKeys(fingerprints, normalizedMapping) {
		matched = true
		hits[key] = struct{}{}
		for _, value := range normalizedMapping[key] {
			addTemplate(key, value)
		}
	}
	if matched {
		for _, key := range []string{"baseline", "_baseline"} {
			for _, value := range normalizedMapping[key] {
				addTemplate(key, value)
			}
		}
	} else {
		for _, key := range []string{"fallback", "_fallback", "baseline", "_baseline"} {
			for _, value := range normalizedMapping[key] {
				addTemplate(key, value)
			}
		}
	}
	slices.Sort(out)
	return templateSelection{
		Templates:       out,
		FingerprintHits: sortedKeys(hits),
		Reasons:         sortedKeys(reasons),
		FallbackFull:    false,
		MatchedAssets:   matchedAssets,
		AssetCount:      assetCount,
		TargetAssets:    targetAssets,
		SkipNuclei:      !matched && len(out) == 0,
	}
}

func matchPOCMapKeys(fingerprints map[string]struct{}, mapping map[string][]string) map[string]struct{} {
	hits := map[string]struct{}{}
	for fingerprint := range fingerprints {
		for key := range mapping {
			if key == "baseline" || key == "_baseline" || !strings.Contains(fingerprint, key) {
				continue
			}
			hits[key] = struct{}{}
		}
	}
	return hits
}

func safeTemplatePath(pocDir, value string) string {
	base, err := filepath.Abs(pocDir)
	if err != nil {
		return ""
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(base, value)
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return ""
	}
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return ""
	}
	return abs
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func logTemplateSelection(pocDir string, selection templateSelection) {
	total := countNucleiTemplates([]string{pocDir})
	selected := total
	if selection.SkipNuclei {
		selected = 0
	} else if len(selection.Templates) > 0 {
		selected = countNucleiTemplates(selection.Templates)
	}
	reduction := 0.0
	if total > 0 {
		reduction = float64(total-selected) * 100 / float64(total)
	}
	hitRate := 0.0
	if selection.AssetCount > 0 {
		hitRate = float64(selection.MatchedAssets) * 100 / float64(selection.AssetCount)
	}
	log.Printf("nuclei templates_total=%d templates_selected=%d template_reduction_ratio=%.1f%% poc_map_hit_rate=%.1f%% poc_map_assets_matched=%d/%d fallback_full_scan=%t skip_nuclei=%t fingerprint_hits=%s template_match_reasons=%s",
		total, selected, reduction, hitRate, selection.MatchedAssets, selection.AssetCount, selection.FallbackFull, selection.SkipNuclei, strings.Join(selection.FingerprintHits, ","), strings.Join(selection.Reasons, ","))
}

func countNucleiTemplates(paths []string) int {
	count := 0
	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			continue
		}
		if !info.IsDir() {
			if isNucleiTemplate(root) {
				count++
			}
			continue
		}
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err == nil && !entry.IsDir() && isNucleiTemplate(path) {
				count++
			}
			return nil
		})
	}
	return count
}

func isNucleiTemplate(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yaml" || ext == ".yml"
}

func assetFingerprints(assets []Asset) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(value string) {
		for _, token := range fingerprintTokens(value) {
			out[token] = struct{}{}
		}
	}
	for _, asset := range assets {
		add(asset.Service)
		add(asset.Protocol)
		add(asset.Server)
		add(asset.Title)
		add(asset.Banner)
		add(asset.Status)
		add(asset.URL)
		add(asset.Vulnerability)
		if asset.Port > 0 {
			add(fmt.Sprintf("port:%d", asset.Port))
		}
		for _, fingerprint := range asset.Fingerprints {
			add(fingerprint)
		}
	}
	return out
}

func fingerprintTokens(value string) []string {
	value = strings.ToLower(strings.Join(strings.Fields(value), " "))
	if value == "" {
		return nil
	}

	out := map[string]struct{}{value: {}}
	cleaned := cleanFingerprint(value)
	if cleaned != "" {
		out[cleaned] = struct{}{}
	}
	compact := fingerprintCompact(value)
	if compact != "" {
		out[compact] = struct{}{}
	}
	for _, alias := range fingerprintAliases(value + " " + cleaned + " " + compact) {
		out[alias] = struct{}{}
	}
	return sortedKeys(out)
}

func cleanFingerprint(value string) string {
	value = strings.NewReplacer(
		"/", " ", "\\", " ", "_", " ", ":", " ", ";", " ", ",", " ",
		"(", " ", ")", " ", "[", " ", "]", " ", "{", " ", "}", " ",
	).Replace(value)
	fields := strings.Fields(value)
	out := fields[:0]
	for _, field := range fields {
		field = strings.Trim(field, ".-")
		if field != "" && !isVersionToken(field) {
			out = append(out, field)
		}
	}
	return strings.Join(out, " ")
}

func isVersionToken(value string) bool {
	hasDigit := false
	for _, r := range value {
		if r >= '0' && r <= '9' {
			hasDigit = true
			continue
		}
		if r == '.' || r == '-' || r == '_' || r == 'v' {
			continue
		}
		return false
	}
	return hasDigit
}

func fingerprintCompact(value string) string {
	return strings.NewReplacer(" ", "", "-", "", "_", "", "/", "", ".", "").Replace(value)
}

func fingerprintAliases(value string) []string {
	aliases := map[string]struct{}{}
	for _, pair := range [][2]string{
		{"apache httpd", "apache"},
		{"microsoft-iis", "iis"},
		{"microsoft iis", "iis"},
		{"apache-coyote", "tomcat"},
		{"tomcat/coyote", "tomcat"},
		{"tomcat coyote", "tomcat"},
		{"elastic", "elasticsearch"},
	} {
		if strings.Contains(value, pair[0]) {
			aliases[pair[1]] = struct{}{}
		}
	}
	for _, name := range []string{"spring", "thinkphp", "wordpress", "jenkins", "weblogic", "nacos", "kibana", "wazuh", "grafana", "prometheus", "gitlab", "harbor", "minio"} {
		if strings.Contains(value, name) {
			aliases[name] = struct{}{}
		}
	}
	return sortedKeys(aliases)
}

func nucleiTargets(host string, assets []Asset) []string {
	seen := map[string]struct{}{}
	add := func(target string) {
		target = strings.TrimSpace(target)
		if target == "" {
			return
		}
		seen[target] = struct{}{}
	}

	// ponytail: target-level precision; add fingerprint-to-template tags only when the POC taxonomy is stable.
	for _, asset := range assets {
		if asset.URL != "" {
			add(asset.URL)
			continue
		}
		if asset.IsWeb {
			add(buildURL(asset))
			continue
		}
		if asset.Port > 0 {
			add(joinHostPort(asset.Target, asset.Port))
		}
	}
	if len(seen) == 0 {
		add(host)
	}

	out := make([]string, 0, len(seen))
	for target := range seen {
		out = append(out, target)
	}
	slices.Sort(out)
	return out
}

func buildURL(asset Asset) string {
	target := asset.Target
	if target == "" {
		return ""
	}
	scheme := asset.Protocol
	if scheme != "http" && scheme != "https" {
		scheme = asset.Service
	}
	if scheme != "http" && scheme != "https" {
		scheme = "http"
	}
	return scheme + "://" + joinHostPort(target, asset.Port)
}

func joinHostPort(host string, port int) string {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 || strings.Contains(host, "://") {
		return host
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), strconv.Itoa(port))
}

func detailString(details map[string]any, key string) string {
	if details == nil {
		return ""
	}
	switch v := details[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case fmt.Stringer:
		return strings.TrimSpace(v.String())
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func detailStrings(details map[string]any, key string) []string {
	if details == nil {
		return nil
	}
	switch v := details[key].(type) {
	case []string:
		return uniqueSorted(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, strings.TrimSpace(fmt.Sprint(item)))
		}
		return uniqueSorted(out)
	case string:
		if v == "" {
			return nil
		}
		parts := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' })
		return uniqueSorted(parts)
	default:
		return nil
	}
}

func detailInt(details map[string]any, key string) int {
	if details == nil {
		return 0
	}
	switch v := details[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	default:
		return 0
	}
}

func firstInt(details map[string]any, keys ...string) int {
	for _, key := range keys {
		if value := detailInt(details, key); value != 0 {
			return value
		}
	}
	return 0
}

func detailBool(details map[string]any, key string) bool {
	if details == nil {
		return false
	}
	switch v := details[key].(type) {
	case bool:
		return v
	case string:
		ok, _ := strconv.ParseBool(strings.TrimSpace(v))
		return ok
	default:
		return false
	}
}
