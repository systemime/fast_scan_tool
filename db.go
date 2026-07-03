package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	db *sql.DB
}

type UpsertResult struct {
	Namespace string   `json:"namespace"`
	HostCount int      `json:"host_count"`
	Timeout   int      `json:"timeout"`
	Added     []string `json:"added"`
	Removed   []string `json:"removed"`
}

type TaskResult struct {
	Namespace string       `json:"namespace"`
	HostCount int          `json:"host_count"`
	Timeout   int          `json:"timeout"`
	Hosts     []HostResult `json:"hosts"`
}

type HostResult struct {
	IP               string     `json:"ip"`
	Status           string     `json:"status"`
	Timeout          int        `json:"timeout"`
	Assets           []Asset    `json:"assets"`
	Vulnerabilities  int        `json:"vulnerabilities"`
	VulnerabilityIDs []string   `json:"vulnerability_ids"`
	StartedAt        *time.Time `json:"started_at,omitempty"`
	FinishedAt       *time.Time `json:"finished_at,omitempty"`
	LastError        string     `json:"last_error,omitempty"`
}

type Asset struct {
	Type          string   `json:"type"`
	Target        string   `json:"target"`
	Port          int      `json:"port,omitempty"`
	Service       string   `json:"service,omitempty"`
	Protocol      string   `json:"protocol,omitempty"`
	URL           string   `json:"url,omitempty"`
	Title         string   `json:"title,omitempty"`
	Server        string   `json:"server,omitempty"`
	Banner        string   `json:"banner,omitempty"`
	Status        string   `json:"status,omitempty"`
	StatusCode    int      `json:"status_code,omitempty"`
	Fingerprints  []string `json:"fingerprints,omitempty"`
	Vulnerability string   `json:"vulnerability,omitempty"`
	IsWeb         bool     `json:"is_web,omitempty"`
}

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.init(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) init(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS namespaces (
	namespace TEXT PRIMARY KEY,
	timeout_seconds INTEGER NOT NULL,
	host_count INTEGER NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
	namespace TEXT NOT NULL,
	ip TEXT NOT NULL,
	status TEXT NOT NULL,
	timeout_seconds INTEGER NOT NULL,
	started_at TEXT,
	finished_at TEXT,
	vulnerabilities INTEGER NOT NULL DEFAULT 0,
	vulnerability_ids TEXT NOT NULL DEFAULT '[]',
	assets TEXT NOT NULL DEFAULT '[]',
	last_error TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL,
	PRIMARY KEY (namespace, ip),
	FOREIGN KEY (namespace) REFERENCES namespaces(namespace) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
`)
	if err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "hosts", "vulnerability_ids", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "hosts", "assets", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
UPDATE hosts SET status = CASE status
	WHEN '未开始' THEN ?
	WHEN '进行中' THEN ?
	WHEN '已完成' THEN ?
	WHEN '超时' THEN ?
	ELSE status
END
`, StatusPending, StatusRunning, StatusDone, StatusTimeout)
	return err
}

func (s *Store) ensureColumn(ctx context.Context, table, column, definition string) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, typ string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `ALTER TABLE `+table+` ADD COLUMN `+column+` `+definition)
	return err
}

func (s *Store) ResetRunning(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET status = ?, started_at = NULL, updated_at = ? WHERE status = ?`, StatusPending, nowText(), StatusRunning)
	return err
}

func (s *Store) UpsertTask(ctx context.Context, namespace string, hosts []string, timeout int) (UpsertResult, error) {
	result := UpsertResult{Namespace: namespace, HostCount: len(hosts), Timeout: timeout}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()

	now := nowText()
	_, err = tx.ExecContext(ctx, `
INSERT INTO namespaces(namespace, timeout_seconds, host_count, updated_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(namespace) DO UPDATE SET
	timeout_seconds = excluded.timeout_seconds,
	host_count = excluded.host_count,
	updated_at = excluded.updated_at
`, namespace, timeout, len(hosts), now)
	if err != nil {
		return result, err
	}

	rows, err := tx.QueryContext(ctx, `SELECT ip, status FROM hosts WHERE namespace = ?`, namespace)
	if err != nil {
		return result, err
	}
	existing := map[string]string{}
	for rows.Next() {
		var ip, status string
		if err := rows.Scan(&ip, &status); err != nil {
			rows.Close()
			return result, err
		}
		existing[ip] = status
	}
	if err := rows.Close(); err != nil {
		return result, err
	}

	want := make(map[string]struct{}, len(hosts))
	for _, host := range hosts {
		want[host] = struct{}{}
	}

	for ip, status := range existing {
		if _, ok := want[ip]; !ok {
			if _, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE namespace = ? AND ip = ?`, namespace, ip); err != nil {
				return result, err
			}
			result.Removed = append(result.Removed, ip)
			continue
		}
		if status == StatusPending {
			if _, err := tx.ExecContext(ctx, `UPDATE hosts SET timeout_seconds = ?, updated_at = ? WHERE namespace = ? AND ip = ?`, timeout, now, namespace, ip); err != nil {
				return result, err
			}
		}
	}

	for _, host := range hosts {
		if _, ok := existing[host]; ok {
			continue
		}
		_, err := tx.ExecContext(ctx, `
INSERT INTO hosts(namespace, ip, status, timeout_seconds, updated_at)
VALUES (?, ?, ?, ?, ?)
`, namespace, host, StatusPending, timeout, now)
		if err != nil {
			return result, err
		}
		result.Added = append(result.Added, host)
	}

	return result, tx.Commit()
}

func (s *Store) GetTask(ctx context.Context, namespace string) (TaskResult, error) {
	var result TaskResult
	err := s.db.QueryRowContext(ctx, `SELECT namespace, timeout_seconds, host_count FROM namespaces WHERE namespace = ?`, namespace).
		Scan(&result.Namespace, &result.Timeout, &result.HostCount)
	if errors.Is(err, sql.ErrNoRows) {
		return result, ErrNotFound
	}
	if err != nil {
		return result, err
	}

	rows, err := s.db.QueryContext(ctx, `
SELECT ip, status, timeout_seconds, vulnerabilities, vulnerability_ids, assets, started_at, finished_at, last_error
FROM hosts
WHERE namespace = ?
ORDER BY ip
`, namespace)
	if err != nil {
		return result, err
	}
	defer rows.Close()

	for rows.Next() {
		var host HostResult
		var started, finished, ids, assets sql.NullString
		if err := rows.Scan(&host.IP, &host.Status, &host.Timeout, &host.Vulnerabilities, &ids, &assets, &started, &finished, &host.LastError); err != nil {
			return result, err
		}
		host.VulnerabilityIDs = parseStringList(ids)
		host.Assets = parseAssets(assets)
		host.StartedAt = parseTime(started)
		host.FinishedAt = parseTime(finished)
		result.Hosts = append(result.Hosts, host)
	}
	return result, rows.Err()
}

func (s *Store) PendingHosts(ctx context.Context) ([]scanJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT namespace, ip FROM hosts WHERE status = ? ORDER BY updated_at, namespace, ip`, StatusPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []scanJob
	for rows.Next() {
		var job scanJob
		if err := rows.Scan(&job.Namespace, &job.IP); err != nil {
			return nil, err
		}
		jobs = append(jobs, job)
	}
	return jobs, rows.Err()
}

func (s *Store) BeginHost(ctx context.Context, namespace, ip string) (timeout int, ok bool, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()

	var status string
	err = tx.QueryRowContext(ctx, `SELECT status, timeout_seconds FROM hosts WHERE namespace = ? AND ip = ?`, namespace, ip).Scan(&status, &timeout)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	if status != StatusPending {
		return 0, false, nil
	}

	now := nowText()
	_, err = tx.ExecContext(ctx, `
UPDATE hosts
SET status = ?, started_at = ?, finished_at = NULL, vulnerabilities = 0, vulnerability_ids = '[]', assets = '[]', last_error = '', updated_at = ?
WHERE namespace = ? AND ip = ? AND status = ?
`, StatusRunning, now, now, namespace, ip, StatusPending)
	if err != nil {
		return 0, false, err
	}
	if err := tx.Commit(); err != nil {
		return 0, false, err
	}
	return timeout, true, nil
}

func (s *Store) CompleteHost(ctx context.Context, namespace, ip string, ids []string, assets []Asset, scanErr error) error {
	lastErr := ""
	if scanErr != nil {
		lastErr = scanErr.Error()
	}
	ids = uniqueSorted(ids)
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	assets = uniqueAssets(assets)
	assetsJSON, err := json.Marshal(assets)
	if err != nil {
		return err
	}
	now := nowText()
	_, err = s.db.ExecContext(ctx, `
UPDATE hosts
SET status = ?, finished_at = ?, vulnerabilities = ?, vulnerability_ids = ?, assets = ?, last_error = ?, updated_at = ?
WHERE namespace = ? AND ip = ? AND status = ?
`, StatusDone, now, len(ids), string(idsJSON), string(assetsJSON), lastErr, now, namespace, ip, StatusRunning)
	return err
}

func (s *Store) TimeoutHost(ctx context.Context, namespace, ip string) error {
	now := nowText()
	_, err := s.db.ExecContext(ctx, `
UPDATE hosts
SET status = ?, finished_at = ?, last_error = 'scan timeout', updated_at = ?
WHERE namespace = ? AND ip = ? AND status = ?
`, StatusTimeout, now, namespace, ip, StatusRunning)
	return err
}

func (s *Store) OverdueHosts(ctx context.Context, now time.Time) ([]scanJob, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT namespace, ip, started_at, timeout_seconds FROM hosts WHERE status = ? AND started_at IS NOT NULL`, StatusRunning)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []scanJob
	for rows.Next() {
		var job scanJob
		var started string
		var timeoutSeconds int
		if err := rows.Scan(&job.Namespace, &job.IP, &started, &timeoutSeconds); err != nil {
			return nil, err
		}
		startedAt, err := time.Parse(time.RFC3339Nano, started)
		if err != nil || now.After(startedAt.Add(time.Duration(timeoutSeconds)*time.Second)) {
			jobs = append(jobs, job)
		}
	}
	return jobs, rows.Err()
}

func nowText() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func parseTime(value sql.NullString) *time.Time {
	if !value.Valid || value.String == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil
	}
	return &t
}

func parseStringList(value sql.NullString) []string {
	if !value.Valid || value.String == "" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(value.String), &out); err != nil {
		return []string{}
	}
	return uniqueSorted(out)
}

func parseAssets(value sql.NullString) []Asset {
	if !value.Valid || value.String == "" {
		return []Asset{}
	}
	var out []Asset
	if err := json.Unmarshal([]byte(value.String), &out); err != nil {
		return []Asset{}
	}
	return uniqueAssets(out)
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func uniqueAssets(values []Asset) []Asset {
	seen := make(map[string]struct{}, len(values))
	out := make([]Asset, 0, len(values))
	for _, value := range values {
		if value.Target == "" {
			continue
		}
		value.Fingerprints = uniqueSorted(value.Fingerprints)
		key := value.Type + "\x00" + value.Target + "\x00" + value.URL + "\x00" + strconv.Itoa(value.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	slices.SortFunc(out, func(a, b Asset) int {
		if a.Target != b.Target {
			return strings.Compare(a.Target, b.Target)
		}
		if a.Port != b.Port {
			return a.Port - b.Port
		}
		if a.URL != b.URL {
			return strings.Compare(a.URL, b.URL)
		}
		return strings.Compare(a.Type, b.Type)
	})
	return out
}
