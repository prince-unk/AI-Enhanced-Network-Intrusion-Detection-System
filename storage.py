import json, hashlib, sqlite3
from pathlib import Path
from typing import Optional

class NIDSStorage:
    def __init__(self, db_path: Optional[str]=None):
        root=Path(__file__).resolve().parent
        self.db_path=Path(db_path) if db_path else root/"data"/"nids.db"
        self.db_path.parent.mkdir(parents=True,exist_ok=True)
        self.init_db()

    def connect(self):
        c=sqlite3.connect(str(self.db_path),timeout=15)
        c.row_factory=sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=15000")
        return c

    @staticmethod
    def js(v): return json.dumps(v,sort_keys=True,ensure_ascii=False,default=str)
    @staticmethod
    def fp(v): return hashlib.sha256(NIDSStorage.js(v).encode()).hexdigest()

    def init_db(self):
        with self.connect() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS events(
              event_id TEXT PRIMARY KEY,event_type TEXT,timestamp TEXT,src_ip TEXT,
              dest_ip TEXT,signature TEXT,raw_json TEXT NOT NULL,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);
            CREATE TABLE IF NOT EXISTS incidents(
              incident_id TEXT PRIMARY KEY,fingerprint TEXT UNIQUE,detection_type TEXT,
              severity TEXT,risk_score INTEGER,source_ip TEXT,destination_ip TEXT,
              signature TEXT,first_seen TEXT,last_seen TEXT,event_count INTEGER,
              description TEXT,recommended_action TEXT,status TEXT,analyst_notes TEXT,
              record_json TEXT NOT NULL,updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status);
            CREATE TABLE IF NOT EXISTS incident_evidence(
              evidence_id INTEGER PRIMARY KEY AUTOINCREMENT,incident_id TEXT NOT NULL,
              fingerprint TEXT NOT NULL,evidence_json TEXT NOT NULL,
              UNIQUE(incident_id,fingerprint),
              FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS ai_cache(
              cache_key TEXT PRIMARY KEY,provider TEXT,model TEXT,result_json TEXT NOT NULL,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS alert_history(
              alert_id TEXT PRIMARY KEY, raw_json TEXT NOT NULL,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE INDEX IF NOT EXISTS idx_alert_history_created ON alert_history(created_at);
            CREATE TABLE IF NOT EXISTS behavioral_detections(
              detection_id TEXT PRIMARY KEY, detection_json TEXT NOT NULL,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE INDEX IF NOT EXISTS idx_behavior_created ON behavioral_detections(created_at);
            CREATE TABLE IF NOT EXISTS analyst_notes(
              note_id INTEGER PRIMARY KEY AUTOINCREMENT,incident_id TEXT,note TEXT,
              created_at TEXT DEFAULT CURRENT_TIMESTAMP,
              FOREIGN KEY(incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS audit_log(
              audit_id INTEGER PRIMARY KEY AUTOINCREMENT,incident_id TEXT,action TEXT,
              old_value TEXT,new_value TEXT,actor TEXT DEFAULT 'analyst',
              created_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS ai_usage(
              usage_date TEXT PRIMARY KEY,request_count INTEGER DEFAULT 0,
              updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS ai_request_log(
              request_id INTEGER PRIMARY KEY AUTOINCREMENT,
              requested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
            );
            CREATE INDEX IF NOT EXISTS idx_ai_request_time ON ai_request_log(requested_at);
            """)
            # Backfill alerts saved before alert_history was introduced.
            c.execute("""
                INSERT OR IGNORE INTO alert_history(alert_id, raw_json, created_at)
                SELECT event_id, raw_json, created_at FROM events
                WHERE lower(coalesce(event_type, '')) = 'alert'
            """)

    def save_event(self,event):
        a=event.get("alert") or {}
        with self.connect() as c:
            event_id = self.fp(event)
            cur=c.execute("""INSERT OR IGNORE INTO events
              (event_id,event_type,timestamp,src_ip,dest_ip,signature,raw_json)
              VALUES(?,?,?,?,?,?,?)""",
              (event_id,event.get("event_type","unknown"),event.get("timestamp"),
               event.get("src_ip"),event.get("dest_ip"),a.get("signature"),self.js(event)))
            if event.get("event_type") == "alert" or event.get("alert"):
                c.execute("INSERT OR IGNORE INTO alert_history(alert_id,raw_json) VALUES(?,?)",
                          (event_id,self.js(event)))
            return cur.rowcount==1

    def save_events(self,events): return sum(self.save_event(e) for e in events)

    def get_events(self,limit=500):
        with self.connect() as c:
            rows=c.execute("SELECT raw_json FROM events ORDER BY rowid DESC LIMIT ?",(int(limit),)).fetchall()
        return [json.loads(r["raw_json"]) for r in reversed(rows)]

    def save_incident(self,incident):
        x=dict(incident); evidence=x.pop("evidence",[]) or []
        iid=str(x["incident_id"])
        fp=x.get("fingerprint") or self.fp({k:x.get(k) for k in
            ("detection_type","source_ip","destination_ip","signature")})
        fields=("detection_type","severity","risk_score","source_ip","destination_ip",
                "signature","first_seen","last_seen","event_count","description",
                "recommended_action","status","analyst_notes")
        with self.connect() as c:
            old=c.execute("SELECT record_json FROM incidents WHERE incident_id=?",(iid,)).fetchone()
            if old:
                prior=json.loads(old["record_json"])
                x["status"]=prior.get("status",x.get("status","Open"))
                x["analyst_notes"]=prior.get("analyst_notes",x.get("analyst_notes",""))
            x.update(incident_id=iid,evidence=evidence)
            vals=[x.get(k) for k in fields]
            c.execute("""INSERT INTO incidents
              (incident_id,fingerprint,detection_type,severity,risk_score,source_ip,
               destination_ip,signature,first_seen,last_seen,event_count,description,
               recommended_action,status,analyst_notes,record_json)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
              ON CONFLICT(incident_id) DO UPDATE SET severity=excluded.severity,
              risk_score=excluded.risk_score,last_seen=excluded.last_seen,
              event_count=excluded.event_count,description=excluded.description,
              recommended_action=excluded.recommended_action,status=excluded.status,
              analyst_notes=excluded.analyst_notes,record_json=excluded.record_json,
              updated_at=CURRENT_TIMESTAMP""",(iid,fp,*vals,self.js(x)))
            for item in evidence:
                c.execute("""INSERT OR IGNORE INTO incident_evidence
                  (incident_id,fingerprint,evidence_json) VALUES(?,?,?)""",
                  (iid,self.fp(item),self.js(item)))

    def get_incidents(self):
        with self.connect() as c:
            rows=c.execute("SELECT record_json FROM incidents ORDER BY risk_score DESC,last_seen DESC").fetchall()
        return [json.loads(r["record_json"]) for r in rows]

    def update_incident(self,iid,status,notes,actor="analyst"):
        if status not in {"Open","Investigating","Resolved"}: raise ValueError("Invalid status")
        with self.connect() as c:
            row=c.execute("SELECT record_json,status,analyst_notes FROM incidents WHERE incident_id=?",(iid,)).fetchone()
            if not row: raise KeyError(iid)
            x=json.loads(row["record_json"]); old_status=row["status"]; old_notes=row["analyst_notes"]
            x["status"]=status; x["analyst_notes"]=notes
            c.execute("UPDATE incidents SET status=?,analyst_notes=?,record_json=?,updated_at=CURRENT_TIMESTAMP WHERE incident_id=?",
                      (status,notes,self.js(x),iid))
            if old_status!=status:
                c.execute("INSERT INTO audit_log(incident_id,action,old_value,new_value,actor) VALUES(?,?,?,?,?)",
                          (iid,"STATUS_CHANGED",old_status,status,actor))
            if old_notes!=notes and notes:
                c.execute("INSERT INTO analyst_notes(incident_id,note) VALUES(?,?)",(iid,notes))
                c.execute("INSERT INTO audit_log(incident_id,action,old_value,new_value,actor) VALUES(?,?,?,?,?)",
                          (iid,"NOTES_UPDATED",old_notes,notes,actor))

    def get_ai_result(self,key):
        with self.connect() as c: row=c.execute("SELECT result_json FROM ai_cache WHERE cache_key=?",(key,)).fetchone()
        return json.loads(row["result_json"]) if row else None

    def save_ai_result(self,key,result,model=""):
        with self.connect() as c:
            c.execute("INSERT OR REPLACE INTO ai_cache(cache_key,provider,model,result_json) VALUES(?,?,?,?)",
                      (key,result.get("provider","unknown"),model,self.js(result)))

    def record_ai_request(self,date):
        with self.connect() as c:
            c.execute("""INSERT INTO ai_usage(usage_date,request_count) VALUES(?,1)
              ON CONFLICT(usage_date) DO UPDATE SET request_count=request_count+1,
              updated_at=CURRENT_TIMESTAMP""",(date,))
            return c.execute("SELECT request_count FROM ai_usage WHERE usage_date=?",(date,)).fetchone()[0]

    def get_ai_request_count(self,date):
        with self.connect() as c:
            row=c.execute("SELECT request_count FROM ai_usage WHERE usage_date=?",(date,)).fetchone()
        return int(row[0]) if row else 0

    def reserve_ai_request(self, daily_limit=498, per_minute_limit=14):
        """Atomically reserve an API request slot; returns (allowed, reason, daily_count)."""
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        day = now.date().isoformat()
        cutoff = (now - timedelta(seconds=60)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        prune_before = (now - timedelta(days=2)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("DELETE FROM ai_request_log WHERE requested_at < ?", (prune_before,))
            row = c.execute("SELECT request_count FROM ai_usage WHERE usage_date=?", (day,)).fetchone()
            daily_count = int(row[0]) if row else 0
            minute_count = c.execute("SELECT COUNT(*) FROM ai_request_log WHERE requested_at >= ?", (cutoff,)).fetchone()[0]
            if daily_count >= int(daily_limit):
                return False, "daily_limit", daily_count
            if minute_count >= int(per_minute_limit):
                return False, "per_minute_limit", daily_count
            c.execute("""INSERT INTO ai_usage(usage_date,request_count) VALUES(?,1)
                         ON CONFLICT(usage_date) DO UPDATE SET request_count=request_count+1,
                         updated_at=CURRENT_TIMESTAMP""", (day,))
            c.execute("INSERT INTO ai_request_log(requested_at) VALUES(?)", (now_iso,))
            return True, "allowed", daily_count + 1

    def save_behavioral_detection(self, detection):
        key = self.fp(detection)
        with self.connect() as c:
            c.execute("INSERT OR IGNORE INTO behavioral_detections(detection_id,detection_json) VALUES(?,?)",
                      (key, self.js(detection)))
        return key

    def get_alert_history(self, limit=500):
        with self.connect() as c:
            rows = c.execute(
                "SELECT raw_json FROM alert_history ORDER BY created_at DESC LIMIT ?",
                (int(limit),)
            ).fetchall()
        return [json.loads(row["raw_json"]) for row in reversed(rows)]

    def get_behavioral_detections(self, limit=500):
        with self.connect() as c:
            rows = c.execute(
                "SELECT detection_json FROM behavioral_detections ORDER BY created_at DESC LIMIT ?",
                (int(limit),)
            ).fetchall()
        return [json.loads(row["detection_json"]) for row in reversed(rows)]

    def get_audit_log(self, incident_id=None, limit=500):
        query = "SELECT * FROM audit_log"
        params = []
        if incident_id is not None:
            query += " WHERE incident_id = ?"
            params.append(str(incident_id))
        query += " ORDER BY audit_id DESC LIMIT ?"
        params.append(int(limit))
        with self.connect() as c:
            rows = c.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def get_incident_evidence(self, incident_id):
        with self.connect() as c:
            rows = c.execute(
                "SELECT fingerprint, evidence_json FROM incident_evidence WHERE incident_id=? ORDER BY evidence_id",
                (str(incident_id),)
            ).fetchall()
        return [
            {"fingerprint": row["fingerprint"], "evidence": json.loads(row["evidence_json"])}
            for row in rows
        ]

    def apply_retention(self, routine_event_cap=20000):
        """Routine events: 7 days and 20k cap; alerts/behaviour: 30 days;
        incidents/evidence/notes/audit: 60 days."""
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        cut7 = (now - timedelta(days=7)).strftime("%Y-%m-%d %H:%M:%S")
        cut30 = (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        cut60 = (now - timedelta(days=60)).strftime("%Y-%m-%d %H:%M:%S")
        deleted = {}
        with self.connect() as c:
            c.execute("BEGIN IMMEDIATE")
            cur=c.execute("DELETE FROM events WHERE lower(coalesce(event_type,'')) != 'alert' AND json_valid(raw_json) AND json_type(raw_json, '$.alert') IS NULL AND created_at < ?",(cut7,))
            deleted["routine_events_age"]=cur.rowcount
            cur=c.execute("""DELETE FROM events WHERE event_id IN (
                SELECT event_id FROM events WHERE lower(coalesce(event_type,'')) != 'alert' AND json_valid(raw_json) AND json_type(raw_json, '$.alert') IS NULL
                ORDER BY rowid DESC LIMIT -1 OFFSET ?)""",(int(routine_event_cap),))
            deleted["routine_events_cap"]=cur.rowcount
            cur=c.execute("DELETE FROM alert_history WHERE created_at < ?",(cut30,))
            deleted["alerts"]=cur.rowcount
            cur = c.execute(
                """
                DELETE FROM events
                WHERE (lower(coalesce(event_type, '')) = 'alert' OR (json_valid(raw_json) AND json_type(raw_json, '$.alert') IS NOT NULL))
                AND created_at < ?
                """,
                (cut30,)
            )
            deleted["alert_events"] = cur.rowcount
            cur=c.execute("DELETE FROM behavioral_detections WHERE created_at < ?",(cut30,))
            deleted["behavioral_detections"]=cur.rowcount
            cur=c.execute("DELETE FROM incidents WHERE updated_at < ?",(cut60,))
            deleted["incidents"]=cur.rowcount
            cur=c.execute("DELETE FROM analyst_notes WHERE created_at < ?",(cut60,))
            deleted["analyst_notes"]=cur.rowcount
            cur=c.execute("DELETE FROM audit_log WHERE created_at < ?",(cut60,))
            deleted["audit_logs"]=cur.rowcount
        return deleted

    def backup(self,destination=None):
        target=Path(destination) if destination else self.db_path.with_suffix(".backup.db")
        target.parent.mkdir(parents=True,exist_ok=True)
        with self.connect() as src,sqlite3.connect(str(target)) as dst: src.backup(dst)
        return target
