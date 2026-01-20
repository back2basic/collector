package storage

import (
	"database/sql"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/back2basic/euregiohosting/collector/model"

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
        up_9981 INTEGER,
        down_9981 INTEGER,
        up_9984_tcp INTEGER,
        down_9984_tcp INTEGER,
        up_9984_udp INTEGER,
        down_9984_udp INTEGER,
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
            up_9981, down_9981,
            up_9984_tcp, down_9984_tcp,
            up_9984_udp, down_9984_udp,
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
			r.Up9981, r.Down9981,
			r.Up9984TCP, r.Down9984TCP,
			r.Up9984UDP, r.Down9984UDP,
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
			r.Up9981, r.Down9981,
			r.Up9984TCP, r.Down9984TCP,
			r.Up9984UDP, r.Down9984UDP,
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
               SUM(up_9981),
               SUM(down_9981),
               SUM(up_9984_tcp),
               SUM(down_9984_tcp),
               SUM(up_9984_udp),
               SUM(down_9984_udp)
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
			&r.Up9981, &r.Down9981,
			&r.Up9984TCP, &r.Down9984TCP,
			&r.Up9984UDP, &r.Down9984UDP,
		)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}

	return out, nil
}
