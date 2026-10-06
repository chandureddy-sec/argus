package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
	"reconx/pkg/models"
)

// DB wraps a pure-Go SQLite connection.
type DB struct {
	conn *sql.DB
}

// DiffResult holds assets that are newly discovered compared to the previous scan.
type DiffResult struct {
	PreviousScanTime time.Time
	NewAssets        []string
}

// Open initializes the SQLite database at the specified path (defaults to cache/reconx.db).
func Open(dbPath string) (*DB, error) {
	if dbPath == "" {
		dbPath = filepath.Join("cache", "reconx.db")
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("database migration failed: %w", err)
	}

	return db, nil
}

func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS targets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_value TEXT UNIQUE NOT NULL,
		target_type TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id INTEGER NOT NULL,
		scanned_at DATETIME NOT NULL,
		execution_time_ms INTEGER NOT NULL,
		total_assets INTEGER NOT NULL,
		live_assets INTEGER NOT NULL,
		FOREIGN KEY(target_id) REFERENCES targets(id)
	);

	CREATE TABLE IF NOT EXISTS assets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER NOT NULL,
		target_id INTEGER NOT NULL,
		hostname TEXT NOT NULL,
		is_alive BOOLEAN NOT NULL,
		resolved_ips TEXT,
		asn TEXT,
		organization TEXT,
		cloud_provider TEXT,
		sources TEXT,
		confidence REAL NOT NULL,
		FOREIGN KEY(scan_id) REFERENCES scans(id),
		FOREIGN KEY(target_id) REFERENCES targets(id)
	);

	CREATE INDEX IF NOT EXISTS idx_target_val ON targets(target_value);
	CREATE INDEX IF NOT EXISTS idx_scan_target ON scans(target_id);
	CREATE INDEX IF NOT EXISTS idx_asset_host ON assets(hostname);
	`
	_, err := d.conn.Exec(schema)
	return err
}

// Close closes the database connection.
func (d *DB) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}

// SaveScan records a completed scan run and calculates attack surface drift.
func (d *DB) SaveScan(
	ctx context.Context,
	t *models.Target,
	graph *models.Graph,
	duration time.Duration,
) (*DiffResult, error) {
	tx, err := d.conn.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	// 1. Get or create target
	var targetID int64
	err = tx.QueryRowContext(ctx, "SELECT id FROM targets WHERE target_value = ?", t.Value).Scan(&targetID)
	if err == sql.ErrNoRows {
		res, err := tx.ExecContext(ctx, "INSERT INTO targets (target_value, target_type) VALUES (?, ?)", t.Value, string(t.Type))
		if err != nil {
			return nil, err
		}
		targetID, _ = res.LastInsertId()
	} else if err != nil {
		return nil, err
	}

	// 2. Check for previous scan to compute drift
	var prevScanID int64
	var prevScanTime time.Time
	prevErr := tx.QueryRowContext(ctx,
		"SELECT id, scanned_at FROM scans WHERE target_id = ? ORDER BY id DESC LIMIT 1",
		targetID,
	).Scan(&prevScanID, &prevScanTime)

	var prevAssets = make(map[string]bool)
	if prevErr == nil && prevScanID > 0 {
		rows, err := tx.QueryContext(ctx, "SELECT hostname FROM assets WHERE scan_id = ?", prevScanID)
		if err == nil {
			for rows.Next() {
				var h string
				if err := rows.Scan(&h); err == nil {
					prevAssets[h] = true
				}
			}
			rows.Close()
		}
	}

	// 3. Insert new scan run
	totalAssets := 0
	liveAssets := 0
	if graph != nil {
		totalAssets = graph.TotalAssets
		liveAssets = graph.LiveAssets
	}

	scanRes, err := tx.ExecContext(ctx,
		"INSERT INTO scans (target_id, scanned_at, execution_time_ms, total_assets, live_assets) VALUES (?, ?, ?, ?, ?)",
		targetID, time.Now().UTC(), duration.Milliseconds(), totalAssets, liveAssets,
	)
	if err != nil {
		return nil, err
	}
	scanID, _ := scanRes.LastInsertId()

	// 4. Insert assets
	var newAssets []string
	if graph != nil {
		stmt, err := tx.PrepareContext(ctx, `
			INSERT INTO assets (scan_id, target_id, hostname, is_alive, resolved_ips, asn, organization, cloud_provider, sources, confidence)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`)
		if err != nil {
			return nil, err
		}
		defer stmt.Close()

		for _, node := range graph.Nodes {
			if len(prevAssets) > 0 && !prevAssets[node.Hostname] {
				newAssets = append(newAssets, node.Hostname)
			}

			ipsStr := strings.Join(node.ResolvedIPs, ",")
			sourcesStr := strings.Join(node.Sources, ",")
			_, err := stmt.ExecContext(ctx,
				scanID, targetID, node.Hostname, node.IsAlive, ipsStr,
				node.ASN, node.Organization, node.CloudProvider, sourcesStr, node.Confidence,
			)
			if err != nil {
				return nil, err
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	var diff *DiffResult
	if len(prevAssets) > 0 {
		diff = &DiffResult{
			PreviousScanTime: prevScanTime,
			NewAssets:        newAssets,
		}
	}

	return diff, nil
}
