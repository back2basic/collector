package storage

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/back2basic/collector/model"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func init() {
	path := os.Getenv("SQLITE_PATH")
	if path == "" {
		path = "data/traffic.db" // fallback
	}

	dir := filepath.Dir(path)
	_ = os.MkdirAll(dir, 0755)

	var err error
	db, err = sql.Open("sqlite3", path)
	if err != nil {
		log.Fatalf("sqlite open: %v", err)
	}

	schema := `
    CREATE TABLE IF NOT EXISTS traffic (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT,
        ip TEXT,
        dns TEXT,
        consensus_up INTEGER,
        consensus_down INTEGER,
        siamux_up INTEGER,
        siamux_down INTEGER,
        quic_up INTEGER,
        quic_down INTEGER,
        timestamp INTEGER
    );
    `
	if _, err := db.Exec(schema); err != nil {
		log.Fatalf("sqlite schema: %v", err)
	}
}

func FlushSQLite(hostname string, rec4 []model.TrafficRecord4, rec6 []model.TrafficRecord6) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
        INSERT INTO traffic (
            hostname, ip, dns,
            consensus_up, consensus_down,
            siamux_up, siamux_down,
            quic_up, quic_down,
            timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range rec4 {
		_, err = stmt.Exec(
			hostname, r.IP, r.DNS,
			r.ConsensusUp, r.ConsensusDown,
			r.SiamuxUp, r.SiamuxDown,
			r.QuicUp, r.QuicDown,
			r.Timestamp,
		)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	for _, r := range rec6 {
		_, err = stmt.Exec(
			hostname, r.IP, r.DNS,
			r.ConsensusUp, r.ConsensusDown,
			r.SiamuxUp, r.SiamuxDown,
			r.QuicUp, r.QuicDown,
			r.Timestamp,
		)
		if err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func QueryDailyTotals() ([]model.AggregatedRecord, error) {
	midnight := time.Now().Truncate(24 * time.Hour).Unix()

	rows, err := db.Query(`
        SELECT ip, dns,
               SUM(consensus_up),
               SUM(consensus_down),
               SUM(siamux_up),
               SUM(siamux_down),
               SUM(quic_up),
               SUM(quic_down)
        FROM traffic
        WHERE timestamp >= ?
        GROUP BY ip
    `, midnight)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.AggregatedRecord

	for rows.Next() {
		var r model.AggregatedRecord
		err := rows.Scan(
			&r.IP, &r.DNS,
			&r.ConsensusUp, &r.ConsensusDown,
			&r.SiamuxUp, &r.SiamuxDown,
			&r.QuicUp, &r.QuicDown,
		)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}

	return out, nil
}
