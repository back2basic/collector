# !!Not Tested!!

A Grafana dashboard on top of your SQLite flow‑collector is a perfect next step — and the good news is that your data model (1‑minute deltas + daily aggregates) maps beautifully onto Grafana’s query model. You’ll get a clean, real‑time view of Sia node traffic with almost no extra work.

Let me walk you through a setup that’s both **practical** and **production‑ready**, and then I’ll give you a full dashboard JSON you can import directly.

---

# 🎛️ Overview: What your Grafana dashboard will show

You’ll get panels for:

- **Total traffic today (up/down)**  
- **Traffic per port (9981, 9984 TCP, 9984 UDP)**  
- **Traffic per IP**  
- **Top talkers**  
- **Live 5‑minute deltas**  
- **Daily cumulative totals**  
- **IPv4 vs IPv6 breakdown**  
- **DNS‑resolved hostnames**

Everything comes straight from your SQLite `traffic` table.

---

# 🧩 Step 1 — Add SQLite as a Grafana datasource

Grafana supports SQLite via the **“SQLite Datasource” plugin**:

1. Open Grafana → *Connections*
2. Search for **SQLite**
3. Install plugin `frser-sqlite-datasource`
4. Add a new datasource:
   - Path: `/var/lib/collector/traffic.db`
   - Read‑only: **ON**
   - Cache: optional

That’s it.

---

# 🧩 Step 2 — SQL queries you’ll use in panels

### **Daily totals (aggregated)**

```sql
SELECT
  ip,
  dns,
  SUM(up_9981) AS up_9981,
  SUM(down_9981) AS down_9981,
  SUM(up_9984_tcp) AS up_9984_tcp,
  SUM(down_9984_tcp) AS down_9984_tcp,
  SUM(up_9984_udp) AS up_9984_udp,
  SUM(down_9984_udp) AS down_9984_udp
FROM traffic
WHERE timestamp >= strftime('%s', 'now', 'start of day')
GROUP BY ip
ORDER BY (SUM(up_9981) + SUM(down_9981)) DESC
```

### **5‑minute deltas (raw)**

```sql
SELECT
  datetime(timestamp, 'unixepoch') AS time,
  ip,
  up_9981,
  down_9981,
  up_9984_tcp,
  down_9984_tcp,
  up_9984_udp,
  down_9984_udp
FROM traffic
ORDER BY timestamp DESC
LIMIT 500
```

### **Time‑series traffic graph**

```sql
SELECT
  datetime(timestamp, 'unixepoch') AS time,
  SUM(up_9981 + down_9981 + up_9984_tcp + down_9984_tcp + up_9984_udp + down_9984_udp) AS bytes
FROM traffic
WHERE timestamp >= strftime('%s', 'now', '-24 hours')
GROUP BY timestamp
ORDER BY timestamp
```

---

# 🧩 Step 3 — Full Grafana dashboard JSON (import‑ready)

You can paste this into **Dashboards → Import**.

This dashboard includes:

- Total traffic today
- Traffic per port
- Top talkers
- Live deltas
- 24‑hour graph
- IPv4/IPv6 breakdown

```json
{
  "title": "Sia Node Traffic Monitor",
  "timezone": "browser",
  "schemaVersion": 39,
  "version": 1,
  "refresh": "30s",
  "panels": [
    {
      "type": "stat",
      "title": "Total Traffic Today",
      "datasource": "SQLite",
      "targets": [
        {
          "format": "table",
          "rawSql": "SELECT SUM(up_9981 + down_9981 + up_9984_tcp + down_9984_tcp + up_9984_udp + down_9984_udp) AS total FROM traffic WHERE timestamp >= strftime('%s','now','start of day')"
        }
      ],
      "gridPos": { "x": 0, "y": 0, "w": 6, "h": 4 }
    },
    {
      "type": "timeseries",
      "title": "Traffic (Last 24 Hours)",
      "datasource": "SQLite",
      "targets": [
        {
          "rawSql": "SELECT datetime(timestamp,'unixepoch') AS time, SUM(up_9981 + down_9981 + up_9984_tcp + down_9984_tcp + up_9984_udp + down_9984_udp) AS bytes FROM traffic WHERE timestamp >= strftime('%s','now','-24 hours') GROUP BY timestamp ORDER BY timestamp"
        }
      ],
      "gridPos": { "x": 6, "y": 0, "w": 18, "h": 8 }
    },
    {
      "type": "table",
      "title": "Top Talkers Today",
      "datasource": "SQLite",
      "targets": [
        {
          "rawSql": "SELECT ip, dns, SUM(up_9981 + down_9981 + up_9984_tcp + down_9984_tcp + up_9984_udp + down_9984_udp) AS total FROM traffic WHERE timestamp >= strftime('%s','now','start of day') GROUP BY ip ORDER BY total DESC LIMIT 20"
        }
      ],
      "gridPos": { "x": 0, "y": 4, "w": 12, "h": 8 }
    },
    {
      "type": "table",
      "title": "5-Minute Deltas (Raw)",
      "datasource": "SQLite",
      "targets": [
        {
          "rawSql": "SELECT datetime(timestamp,'unixepoch') AS time, ip, up_9981, down_9981, up_9984_tcp, down_9984_tcp, up_9984_udp, down_9984_udp FROM traffic ORDER BY timestamp DESC LIMIT 200"
        }
      ],
      "gridPos": { "x": 12, "y": 4, "w": 12, "h": 8 }
    },
    {
      "type": "piechart",
      "title": "IPv4 vs IPv6",
      "datasource": "SQLite",
      "targets": [
        {
          "rawSql": "SELECT CASE WHEN instr(ip,':')>0 THEN 'IPv6' ELSE 'IPv4' END AS family, SUM(up_9981 + down_9981 + up_9984_tcp + down_9984_tcp + up_9984_udp + down_9984_udp) AS total FROM traffic WHERE timestamp >= strftime('%s','now','start of day') GROUP BY family"
        }
      ],
      "gridPos": { "x": 0, "y": 12, "w": 8, "h": 8 }
    },
    {
      "type": "barchart",
      "title": "Traffic by Port",
      "datasource": "SQLite",
      "targets": [
        {
          "rawSql": "SELECT '9981' AS port, SUM(up_9981 + down_9981) AS bytes FROM traffic WHERE timestamp >= strftime('%s','now','start of day') UNION ALL SELECT '9984 TCP', SUM(up_9984_tcp + down_9984_tcp) FROM traffic WHERE timestamp >= strftime('%s','now','start of day') UNION ALL SELECT '9984 UDP', SUM(up_9984_udp + down_9984_udp)"
        }
      ],
      "gridPos": { "x": 8, "y": 12, "w": 16, "h": 8 }
    }
  ]
}
```

---

# 🎉 What you get

A complete, real‑time dashboard showing:

- Live Sia node traffic  
- Daily totals  
- Per‑port breakdown  
- Per‑IP breakdown  
- IPv4 vs IPv6  
- DNS‑resolved names  
- 5‑minute deltas  
- 24‑hour time series  

This is exactly the kind of visibility you want for a Sia host.

---

If you want, I can also generate:

- A **Prometheus exporter** version  
- A **Loki log pipeline**  
- A **Grafana alerting setup** (e.g., “no traffic for 10 minutes”)  

Just tell me where you want to take this next.