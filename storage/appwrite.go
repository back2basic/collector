package storage

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/back2basic/collector/model"

	"github.com/appwrite/sdk-for-go/appwrite"
	"github.com/appwrite/sdk-for-go/client"
	"github.com/appwrite/sdk-for-go/tablesdb"
)

var sdk *Appwrite

type Appwrite struct {
	client *client.Client
	db     *tablesdb.TablesDB
}

func init() {
	endpoint := os.Getenv("APPWRITE_ENDPOINT")
	project := os.Getenv("APPWRITE_PROJECT")
	apiKey := os.Getenv("APPWRITE_API_KEY")

	if endpoint == "" || project == "" || apiKey == "" {
		log.Println("APPWRITE: missing environment variables, Appwrite disabled, external flush disabled")
		return
	}

	client := appwrite.NewClient(
		appwrite.WithEndpoint(endpoint),
		appwrite.WithProject(project),
		appwrite.WithKey(apiKey),
	)

	db := tablesdb.New(client)

	sdk = &Appwrite{
		client: &client,
		db:     db,
	}
}

func makeRowID(hostname, ip, day string) string {
	h := sha1.New()
	h.Write([]byte(hostname))
	h.Write([]byte(ip))
	h.Write([]byte(day))
	sum := hex.EncodeToString(h.Sum(nil))
	return sum[:32] // Appwrite max 36 chars, keep 32 }
}

func PushDailyToAppwrite(hostname string, rows []model.AggregatedRecord) error {
	if sdk == nil || sdk.client == nil {
		return nil
	}

	dbID := os.Getenv("APPWRITE_DATABASE")
	tableID := os.Getenv("APPWRITE_TABLE")

	if dbID == "" || tableID == "" {
		return fmt.Errorf("missing APPWRITE_DATABASE or APPWRITE_TABLE")
	}

	day := time.Now().Format("2006-01-02")

	totalRows := 0
	for _, r := range rows {
		rowID := makeRowID(hostname, r.IP, day)

		// skip if value are 0
		if r.ConsensusUp == 0 &&
			r.ConsensusDown == 0 &&
			r.SiamuxUp == 0 &&
			r.SiamuxDown == 0 &&
			r.QuicUp == 0 &&
			r.QuicDown == 0 {
			continue
		}

		data := map[string]interface{}{
			"hostname":      hostname,
			"ip":            r.IP,
			"dns":           r.DNS,
			"day":           day,
			"up_9981":       r.ConsensusUp,
			"down_9981":     r.ConsensusDown,
			"up_9984_tcp":   r.SiamuxUp,
			"down_9984_tcp": r.SiamuxDown,
			"up_9984_udp":   r.QuicUp,
			"down_9984_udp": r.QuicDown,
			// "updated_at":    time.Now().Unix(),
		}

		// log.Println("APPWRITE: upserting row", data)

		_, err := sdk.db.UpsertRow(dbID, tableID, rowID, sdk.db.WithUpsertRowData(data))
		if err != nil {
			log.Printf("APPWRITE: failed to upsert %s: %v", rowID, err)
		}
		totalRows++
		// _, err := sdk.db.UpdateRow(dbID, tableID, rowID, sdk.db.WithUpdateRowData(data))
		// if err != nil {
		// 	_, err = sdk.db.CreateRow(dbID, tableID, rowID, data)
		// 	if err != nil {
		// 		log.Printf("APPWRITE: failed to upsert %s: %v", rowID, err)
		// 	}
		// }
	}

	log.Printf("APPWRITE: pushed %d rows to Appwrite", totalRows)
	return nil
}

// func ClearTable() error {
// 	if sdk == nil || sdk.client == nil {
// 		log.Println("APPWRITE: Appwrite SDK not initialized, skipping table clear")
// 		return nil
// 	}

// 	dbID := os.Getenv("APPWRITE_DATABASE")
// 	tableID := os.Getenv("APPWRITE_TABLE")

// 	if dbID == "" || tableID == "" {
// 		return fmt.Errorf("missing APPWRITE_DATABASE or APPWRITE_TABLE")
// 	}

// 	rows, err := sdk.db.ListRows(dbID, tableID, sdk.db.WithListRowsQueries([]string{query.Limit(500)}))
// 	if err != nil {
// 		return err
// 	}

// 	if rows.Total == 0 {
// 		log.Println("APPWRITE: no rows to delete")
// 		return nil
// 	}
// 	// keep looping and fetching until rows.Total = 0
// 	for rows.Total > 0 {
// 		for _, row := range rows.Rows {
// 			_, err := sdk.db.DeleteRow(dbID, tableID, row.Id)
// 			if err != nil {
// 				log.Printf("APPWRITE: failed to delete row: %v", err)
// 			}
// 		}
// 		rows, err = sdk.db.ListRows(dbID, tableID, sdk.db.WithListRowsQueries([]string{query.Limit(500)}))
// 		if err != nil {
// 			return err
// 		}
// 		log.Printf("APPWRITE: deleted %d rows", len(rows.Rows))
// 	}
// 	return nil
// }
