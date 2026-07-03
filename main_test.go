package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fscan "github.com/shadow1ng/fscan/pkg/fscan"
)

func TestUpsertTaskSyncsHosts(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	first, err := store.UpsertTask(ctx, "ns1", []string{"10.0.0.2", "10.0.0.1"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if first.HostCount != 2 || len(first.Added) != 2 || len(first.Removed) != 0 {
		t.Fatalf("unexpected first upsert: %+v", first)
	}

	second, err := store.UpsertTask(ctx, "ns1", []string{"10.0.0.2", "10.0.0.3"}, 20)
	if err != nil {
		t.Fatal(err)
	}
	if second.HostCount != 2 || len(second.Added) != 1 || second.Added[0] != "10.0.0.3" || len(second.Removed) != 1 || second.Removed[0] != "10.0.0.1" {
		t.Fatalf("unexpected second upsert: %+v", second)
	}

	task, err := store.GetTask(ctx, "ns1")
	if err != nil {
		t.Fatal(err)
	}
	if task.HostCount != 2 || len(task.Hosts) != 2 {
		t.Fatalf("unexpected task: %+v", task)
	}
	for _, host := range task.Hosts {
		if host.IP == "10.0.0.1" {
			t.Fatalf("removed host still present: %+v", task.Hosts)
		}
		if host.Status != StatusPending {
			t.Fatalf("unexpected status for %+v", host)
		}
	}

	timeout, ok, err := store.BeginHost(ctx, "ns1", "10.0.0.2")
	if err != nil || !ok || timeout != 20 {
		t.Fatalf("begin timeout=%d ok=%v err=%v", timeout, ok, err)
	}
	assets := []Asset{{
		Type:         "SERVICE",
		Target:       "10.0.0.2",
		Port:         8080,
		Service:      "http",
		URL:          "http://10.0.0.2:8080",
		Title:        "admin",
		Fingerprints: []string{"nginx", "nginx"},
		IsWeb:        true,
	}}
	if err := store.CompleteHost(ctx, "ns1", "10.0.0.2", []string{"cve-2024-0002", "cve-2024-0001", "cve-2024-0001"}, assets, nil); err != nil {
		t.Fatal(err)
	}
	task, err = store.GetTask(ctx, "ns1")
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range task.Hosts {
		if host.IP != "10.0.0.2" {
			continue
		}
		if host.Status != StatusDone || host.Vulnerabilities != 2 || strings.Join(host.VulnerabilityIDs, ",") != "cve-2024-0001,cve-2024-0002" {
			t.Fatalf("unexpected completed host: %+v", host)
		}
		if len(host.Assets) != 1 || host.Assets[0].URL != "http://10.0.0.2:8080" || strings.Join(host.Assets[0].Fingerprints, ",") != "nginx" {
			t.Fatalf("unexpected assets: %+v", host.Assets)
		}
	}
}

func TestFscanResultAssetsAndNucleiTargets(t *testing.T) {
	assets := uniqueAssets([]Asset{
		assetFromFscanResult(fscan.Result{
			Type:   fscan.ResultTypeService,
			Target: "10.0.0.2:8443",
			Status: "ok",
			Details: map[string]any{
				"port":         8443,
				"service":      "https",
				"protocol":     "https",
				"title":        "Dashboard",
				"server":       "nginx",
				"fingerprints": []any{"Spring", "nginx", "Spring"},
				"is_web":       true,
			},
		}),
		assetFromFscanResult(fscan.Result{
			Type:    fscan.ResultTypePort,
			Target:  "10.0.0.2",
			Details: map[string]any{"port": 22},
		}),
	})

	targets := nucleiTargets("10.0.0.2", assets)
	if strings.Join(targets, ",") != "10.0.0.2:22,https://10.0.0.2:8443" {
		t.Fatalf("unexpected nuclei targets: %+v", targets)
	}
	for _, asset := range assets {
		if asset.Port == 8443 && (asset.URL != "https://10.0.0.2:8443" || strings.Join(asset.Fingerprints, ",") != "Spring,nginx") {
			t.Fatalf("unexpected web asset: %+v", asset)
		}
	}
}

func TestFscanDetectPluginsExcludeAuthPOCAndLocalEffect(t *testing.T) {
	plugins := fscanDetectPlugins()
	if len(plugins) == 0 {
		t.Fatal("expected at least one fscan detect plugin")
	}

	infos := map[string]fscan.PluginInfo{}
	for _, info := range fscan.ListPlugins() {
		infos[info.Name] = info
	}
	for _, name := range plugins {
		info, ok := infos[name]
		if !ok {
			t.Fatalf("plugin %q not found in fscan metadata", name)
		}
		if !info.Default || !info.Safe || !hasAnyFscanCapability(info.Capabilities, fscan.PluginCapabilityDetect) {
			t.Fatalf("plugin %q is not a default safe detect plugin: %+v", name, info)
		}
		if hasAnyFscanCapability(info.Capabilities,
			fscan.PluginCapabilityAuthCheck,
			fscan.PluginCapabilityBrute,
			fscan.PluginCapabilityPOC,
			fscan.PluginCapabilityLocalEffect,
		) {
			t.Fatalf("plugin %q has forbidden capabilities: %+v", name, info.Capabilities)
		}
	}
}

func TestParsePortList(t *testing.T) {
	ports, err := parsePortList("443,80,443")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join([]string{formatPortList(ports)}, "") != "80,443" {
		t.Fatalf("unexpected ports: %+v", ports)
	}
	if _, err := parsePortList("0"); err == nil {
		t.Fatal("expected invalid port error")
	}
}

func TestLoadConfigNucleiTimeoutEnv(t *testing.T) {
	t.Setenv("VST_NUCLEI_TIMEOUT", "2")
	t.Setenv("VST_NUCLEI_HOST_CONCURRENCY", "20")
	t.Setenv("VST_HTTP_FINGERPRINT_TIMEOUT", "4")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NucleiTimeout != 2 {
		t.Fatalf("unexpected nuclei timeout: %d", cfg.NucleiTimeout)
	}
	if cfg.NucleiHostConcurrency != 20 {
		t.Fatalf("unexpected nuclei host concurrency: %d", cfg.NucleiHostConcurrency)
	}
	if cfg.HTTPFingerprintTimeout != 4 {
		t.Fatalf("unexpected http fingerprint timeout: %d", cfg.HTTPFingerprintTimeout)
	}
}

func TestEnrichHTTPFingerprints(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("X-Powered-By", "Spring Boot")
		_, _ = w.Write([]byte(`<html><title>Jenkins</title></html>`))
	}))
	defer server.Close()

	assets := enrichHTTPFingerprints(context.Background(), Config{HTTPFingerprintTimeout: 1}, []Asset{{
		Target: "127.0.0.1",
		URL:    server.URL,
		IsWeb:  true,
	}})
	fingerprints := assetFingerprints(assets)
	for _, want := range []string{"nginx", "spring", "jenkins"} {
		if _, ok := fingerprints[want]; !ok {
			t.Fatalf("missing fingerprint %q in %+v", want, fingerprints)
		}
	}
}

func TestSelectNucleiTemplates(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "poc-map.json")
	if err := os.WriteFile(mapPath, []byte(`{
  "baseline": ["http/generic/"],
  "nginx": ["http/cves/nginx/"],
  "redis": ["network/redis/"]
}`), 0644); err != nil {
		t.Fatal(err)
	}
	templates := selectNucleiTemplates("/poc", mapPath, []Asset{{
		Service:      "http",
		Fingerprints: []string{"nginx"},
	}})
	if strings.Join(templates, ",") != "/poc/http/cves/nginx,/poc/http/generic" {
		t.Fatalf("unexpected templates: %+v", templates)
	}
	noFallbackMap := filepath.Join(dir, "poc-map-no-fallback.json")
	if err := os.WriteFile(noFallbackMap, []byte(`{"nginx":["http/cves/nginx/"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	selection := selectNucleiTemplatesWithStats("/poc", noFallbackMap, []Asset{{Service: "ssh"}})
	if len(selection.Templates) != 0 || !selection.SkipNuclei || selection.FallbackFull {
		t.Fatalf("expected skip on unmatched poc map, got %+v", selection)
	}
}

func TestSelectNucleiTemplatesUsesFallbackWithoutFullScan(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "poc-map.json")
	if err := os.WriteFile(mapPath, []byte(`{
  "nginx": ["http/cves/nginx/"],
  "_fallback": ["http/generic/"]
}`), 0644); err != nil {
		t.Fatal(err)
	}
	selection := selectNucleiTemplatesWithStats("/poc", mapPath, []Asset{{Service: "ssh"}})
	if got := strings.Join(selection.Templates, ","); got != "/poc/http/generic" {
		t.Fatalf("unexpected fallback templates: %s", got)
	}
	if selection.SkipNuclei || selection.FallbackFull {
		t.Fatalf("unexpected fallback flags: %+v", selection)
	}
}

func TestSelectNucleiTemplatesNormalizesFingerprintsAndStats(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "poc-map.json")
	if err := os.WriteFile(mapPath, []byte(`{
  "tomcat": ["http/cves/tomcat/"],
  "iis": ["http/cves/iis/"],
  "apache": ["http/cves/apache/"],
  "spring": ["http/cves/spring/"],
  "_baseline": ["http/generic/"]
}`), 0644); err != nil {
		t.Fatal(err)
	}

	selection := selectNucleiTemplatesWithStats("/poc", mapPath, []Asset{
		{Server: "Apache-Coyote/1.1"},
		{Server: "Microsoft-IIS/10.0"},
		{Banner: "Apache httpd 2.4.52"},
		{Fingerprints: []string{"Spring Boot 2.7.1"}},
		{Service: "ssh"},
	})
	if got := strings.Join(selection.FingerprintHits, ","); got != "apache,iis,spring,tomcat" {
		t.Fatalf("unexpected hits: %s", got)
	}
	if selection.AssetCount != 5 || selection.MatchedAssets != 4 || selection.FallbackFull {
		t.Fatalf("unexpected stats: %+v", selection)
	}
	if len(selection.TargetAssets) != 4 {
		t.Fatalf("unexpected target assets: %+v", selection.TargetAssets)
	}
}

func TestSelectNucleiTemplatesRejectsOutsidePOCDir(t *testing.T) {
	dir := t.TempDir()
	mapPath := filepath.Join(dir, "poc-map.json")
	if err := os.WriteFile(mapPath, []byte(`{"nginx":["../secret.yaml","http/nginx.yaml"]}`), 0644); err != nil {
		t.Fatal(err)
	}
	templates := selectNucleiTemplates(dir, mapPath, []Asset{{Server: "nginx"}})
	if len(templates) != 1 || templates[0] != filepath.Join(dir, "http/nginx.yaml") {
		t.Fatalf("unexpected templates: %+v", templates)
	}
}

func TestScanCLIHostsConcurrentPreservesOrder(t *testing.T) {
	var active int32
	var maxActive int32
	scan := func(ctx context.Context, namespace, ip string) (hostScanResult, error) {
		current := atomic.AddInt32(&active, 1)
		for {
			max := atomic.LoadInt32(&maxActive)
			if current <= max || atomic.CompareAndSwapInt32(&maxActive, max, current) {
				break
			}
		}
		time.Sleep(30 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return hostScanResult{VulnerabilityIDs: []string{"id-" + ip}}, nil
	}

	results := scanCLIHosts(context.Background(), "ns1", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 1, 2, scan)
	if atomic.LoadInt32(&maxActive) < 2 {
		t.Fatalf("expected concurrent scans, max active=%d", maxActive)
	}
	if got := results[0].IP + "," + results[1].IP + "," + results[2].IP; got != "10.0.0.1,10.0.0.2,10.0.0.3" {
		t.Fatalf("unexpected result order: %s", got)
	}
	if results[2].Vulnerabilities != 1 || strings.Join(results[2].VulnerabilityIDs, ",") != "id-10.0.0.3" {
		t.Fatalf("unexpected result: %+v", results[2])
	}
}

func TestScanCLIHostsStopsSubmittingAfterContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	scan := func(ctx context.Context, namespace, ip string) (hostScanResult, error) {
		atomic.AddInt32(&calls, 1)
		close(started)
		cancel()
		<-release
		return hostScanResult{}, nil
	}

	done := make(chan []cliHostResult, 1)
	go func() {
		done <- scanCLIHosts(ctx, "ns1", []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, 1, 1, scan)
	}()
	<-started
	time.Sleep(10 * time.Millisecond)
	close(release)
	results := <-done

	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("scan calls=%d want 1", calls)
	}
	if results[1].Error == "" || results[2].Error == "" {
		t.Fatalf("expected remaining hosts to record cancellation: %+v", results)
	}
}

func TestScanAPIStoresAndQueriesLocalOnly(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	handler := localOnly((&app{store: store}).routes())
	post := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(`{"namespace":"ns1","ip_hosts":["10.0.0.1"],"timeout":7}`))
	post.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, post)
	if rec.Code != http.StatusOK {
		t.Fatalf("post status=%d body=%s", rec.Code, rec.Body.String())
	}
	var upsert UpsertResult
	if err := json.NewDecoder(rec.Body).Decode(&upsert); err != nil {
		t.Fatal(err)
	}
	if upsert.HostCount != 1 || upsert.Timeout != 7 {
		t.Fatalf("unexpected upsert: %+v", upsert)
	}

	get := httptest.NewRequest(http.MethodGet, "/scan/ns1", nil)
	get.RemoteAddr = "127.0.0.1:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, get)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", rec.Code, rec.Body.String())
	}
	var task TaskResult
	if err := json.NewDecoder(rec.Body).Decode(&task); err != nil {
		t.Fatal(err)
	}
	if len(task.Hosts) != 1 || task.Hosts[0].Status != StatusPending || task.Hosts[0].IP != "10.0.0.1" {
		t.Fatalf("unexpected task: %+v", task)
	}

	remote := httptest.NewRequest(http.MethodGet, "/scan/ns1", nil)
	remote.RemoteAddr = "8.8.8.8:1234"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, remote)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestScanAPIAcceptsBatchPost(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	handler := localOnly((&app{store: store}).routes())
	body := `[
  {"namespace":"ns1","ip_hosts":["10.0.0.2","10.0.0.1"],"timeout":7},
  {"namespace":"ns2","ip_hosts":["10.0.1.1"],"timeout":9}
]`
	post := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(body))
	post.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, post)
	if rec.Code != http.StatusOK {
		t.Fatalf("post status=%d body=%s", rec.Code, rec.Body.String())
	}
	var upserts []UpsertResult
	if err := json.NewDecoder(rec.Body).Decode(&upserts); err != nil {
		t.Fatal(err)
	}
	if len(upserts) != 2 || upserts[0].Namespace != "ns1" || upserts[0].HostCount != 2 || upserts[1].Namespace != "ns2" || upserts[1].HostCount != 1 {
		t.Fatalf("unexpected batch response: %+v", upserts)
	}

	for namespace, want := range map[string]int{"ns1": 2, "ns2": 1} {
		task, err := store.GetTask(context.Background(), namespace)
		if err != nil {
			t.Fatal(err)
		}
		if len(task.Hosts) != want {
			t.Fatalf("namespace %s hosts=%d want=%d", namespace, len(task.Hosts), want)
		}
	}
}

func TestScanAPIRejectsUnknownBatchField(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	handler := localOnly((&app{store: store}).routes())
	post := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(`[{"namespace":"ns1","ip_hosts":["10.0.0.1"],"unknown":1}]`))
	post.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, post)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("post status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestScanAPIRejectsEmptyHosts(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "tasks.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	handler := localOnly((&app{store: store}).routes())
	post := httptest.NewRequest(http.MethodPost, "/scan", strings.NewReader(`{"namespace":"ns1","ip_hosts":[" "]}`))
	post.RemoteAddr = "127.0.0.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, post)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "ip_hosts") {
		t.Fatalf("post status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestRunScanCLIRejectsMissingNamespace(t *testing.T) {
	code, ok := runScanCLI([]string{"scan", "-ips", "10.0.0.1", "-out", filepath.Join(t.TempDir(), "out.json")})
	if !ok || code != 2 {
		t.Fatalf("runScanCLI ok=%v code=%d, want ok=true code=2", ok, code)
	}
}

func TestRunHelp(t *testing.T) {
	code, ok := runHelp([]string{"--help"})
	if !ok || code != 0 {
		t.Fatalf("runHelp ok=%v code=%d, want ok=true code=0", ok, code)
	}
}

func TestRunScanCLIHelp(t *testing.T) {
	code, ok := runScanCLI([]string{"scan", "-h"})
	if !ok || code != 0 {
		t.Fatalf("runScanCLI help ok=%v code=%d, want ok=true code=0", ok, code)
	}
}
