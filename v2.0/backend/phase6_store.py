import json

from .database import utc_now
from .errors import NotFoundError

class Phase6Store:
    def __init__(self,database):self.database=database
    def list_iocs(self,enabled_only=False):
        query="SELECT * FROM iocs"+(" WHERE enabled = 1" if enabled_only else "")+" ORDER BY type, value"
        with self.database.connect() as connection:rows=connection.execute(query).fetchall()
        return [{**dict(row),"enabled":bool(row["enabled"])} for row in rows]
    def save_ioc(self,ioc):
        now=utc_now()
        with self.database.connect() as connection:
            connection.execute("""INSERT INTO iocs(created_at,updated_at,type,value,description,enabled) VALUES(?,?,?,?,?,?) ON CONFLICT(type,value) DO UPDATE SET updated_at=excluded.updated_at,description=excluded.description,enabled=excluded.enabled""",(now,now,ioc["type"],ioc["value"],ioc["description"],int(ioc["enabled"])))
            row=connection.execute("SELECT * FROM iocs WHERE type=? AND value=?",(ioc["type"],ioc["value"])).fetchone()
        return {**dict(row),"enabled":bool(row["enabled"])}
    def delete_ioc(self,ioc_id):
        with self.database.connect() as connection:cursor=connection.execute("DELETE FROM iocs WHERE id=?",(ioc_id,))
        if not cursor.rowcount:raise NotFoundError("IOC not found.")
    def save_hunt_run(self,result,source_name):
        payload={**result,"sourceName":source_name}
        with self.database.connect() as connection:cursor=connection.execute("INSERT INTO hunt_runs(created_at,hunt_id,source_name,match_count,payload) VALUES(?,?,?,?,?)",(utc_now(),result["hunt"]["id"],source_name,result["matchCount"],json.dumps(payload,ensure_ascii=False)))
        return cursor.lastrowid
    def list_hunt_runs(self,limit=50):
        with self.database.connect() as connection:rows=connection.execute("SELECT id,created_at,hunt_id,source_name,match_count FROM hunt_runs ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
        return [dict(row) for row in rows]
