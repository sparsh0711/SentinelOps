import os
import tempfile
from pathlib import Path
from urllib.parse import parse_qs

from . import __version__
from .errors import ApiError
from .hunting import HUNTS, attack_heatmap, investigation_timeline, match_iocs, normalize_ioc, run_hunt
from .phase6_store import Phase6Store
from .reports import report_payload
from .sigma import convert_sigma
from .validation import bounded_int, validate_analysis, validate_detection_settings, validate_evtx_filename, validate_incident, validate_incident_note, validate_incident_update, validate_rule
from .windows import ALLOWED_CHANNELS, collect, parse_evtx

class Api:
    def __init__(self,settings,database,rules,summary_engine=None):self.settings=settings;self.database=database;self.rules=rules;self.summary_engine=summary_engine;self.phase6=Phase6Store(database)
    def get(self,path,query):
        params=parse_qs(query)
        if path=="/api/v2/status":return {"version":__version__,"online":True,"platform":os.name,"windowsCollection":os.name=="nt","api":"/api/v2","aiSummary":self.summary_engine.status() if self.summary_engine else {"configured":False,"provider":"unavailable"}},200
        if path=="/api/v2/analyses":return {"analyses":self.database.list_analyses(bounded_int(params.get("limit",[100])[0],"limit",100,maximum=100))},200
        if path=="/api/v2/hunts":return {"hunts":HUNTS,"runs":self.phase6.list_hunt_runs()},200
        if path=="/api/v2/iocs":return {"iocs":self.phase6.list_iocs()},200
        if path=="/api/v2/incidents":return {"incidents":self.database.list_incidents(bounded_int(params.get("limit",[100])[0],"limit",100,maximum=100),params.get("status",[""])[0] or None)},200
        if path.startswith("/api/v2/incidents/") and path.endswith("/summaries"):
            incident_id=self._extract_nested_id(path,"incidents","summaries");self.database.get_incident(incident_id);return {"summaries":self.database.list_incident_summaries(incident_id)},200
        if path.startswith("/api/v2/incidents/") and path.endswith("/investigation-timeline"):
            incident_id=self._extract_nested_id(path,"incidents","investigation-timeline");return {"timeline":investigation_timeline(self.database.get_incident(incident_id))},200
        if path.startswith("/api/v2/incidents/"):
            try:incident_id=int(path.rsplit("/",1)[-1])
            except ValueError as error:raise ApiError("Incident ID must be an integer.") from error
            return self.database.get_incident(incident_id),200
        if path=="/api/v2/rules":return {"rules":self.rules.list_rules()},200
        if path.startswith("/api/v2/rules/"):return self.rules.get_rule(path.rsplit("/",1)[-1]),200
        if path=="/api/v2/detection-settings":return self.rules.get_settings(),200
        if path.startswith("/api/v2/analyses/"):
            try:analysis_id=int(path.rsplit("/",1)[-1])
            except ValueError as error:raise ApiError("Analysis ID must be an integer.") from error
            return self.database.get_analysis(analysis_id),200
        if path=="/api/v2/events/windows":
            channel=params.get("channel",["Security"])[0];maximum=bounded_int(params.get("max",[500])[0],"max",500,maximum=self.settings.max_events);incremental=params.get("incremental",["true"])[0].lower()!="false";previous=self.database.get_checkpoint(channel) if incremental else 0;events=collect(channel,maximum,previous);record_ids=[int(event["record_id"]) for event in events if str(event.get("record_id","")).isdigit()];checkpoint=max(record_ids,default=previous)
            if incremental and checkpoint:self.database.save_checkpoint(channel,checkpoint)
            return {"events":events,"sourceName":f"Live: {channel}","incremental":incremental,"previousCheckpoint":previous,"checkpoint":checkpoint,"newCount":len(events)},200
        raise ApiError("API endpoint not found.",status=404,code="not_found")
    def post_json(self,path,payload):
        if path=="/api/v2/analyses":analysis=validate_analysis(payload);return {"saved":True,"id":self.database.save_analysis(analysis)},201
        if path=="/api/v2/hunts/run":result=run_hunt(payload.get("huntId"),payload.get("events"));result["runId"]=self.phase6.save_hunt_run(result,str(payload.get("sourceName") or "Unnamed source")[:255]);return result,201
        if path=="/api/v2/iocs":return self.phase6.save_ioc(normalize_ioc(payload)),201
        if path=="/api/v2/iocs/delete":
            try:ioc_id=int(payload.get("id"))
            except (TypeError,ValueError) as error:raise ApiError("IOC ID must be an integer.",code="invalid_ioc") from error
            self.phase6.delete_ioc(ioc_id);return {"deleted":True,"id":ioc_id},200
        if path=="/api/v2/iocs/match":return match_iocs(payload.get("events"),self.phase6.list_iocs(enabled_only=True)),200
        if path=="/api/v2/rules/import-sigma":return self.rules.save_rule(convert_sigma(payload.get("rule") or payload.get("text")),source="sigma"),201
        if path=="/api/v2/attack/heatmap":return {"techniques":attack_heatmap(payload.get("alerts"))},200
        if path=="/api/v2/incidents":return self.database.create_incident(validate_incident(payload)),201
        if path.startswith("/api/v2/incidents/") and path.endswith("/summaries"):
            if not self.summary_engine:raise ApiError("Incident summary engine is unavailable.",status=503,code="ai_unavailable")
            incident_id=self._extract_nested_id(path,"incidents","summaries");return self.database.save_incident_summary(incident_id,self.summary_engine.generate(self.database.get_incident(incident_id))),201
        if path.startswith("/api/v2/incidents/") and path.endswith("/reports"):
            incident_id=self._extract_nested_id(path,"incidents","reports");format_name=str(payload.get("format") or "html").lower()
            if format_name not in {"html","pdf"}:raise ApiError("Report format must be html or pdf.",code="invalid_report_format")
            return report_payload(self.database.get_incident(incident_id),format_name),200
        if path.startswith("/api/v2/incidents/") and path.endswith("/update"):incident_id=self._extract_nested_id(path,"incidents","update");return self.database.update_incident(incident_id,validate_incident_update(payload)),200
        if path.startswith("/api/v2/incidents/") and path.endswith("/notes"):incident_id=self._extract_nested_id(path,"incidents","notes");return self.database.add_incident_note(incident_id,validate_incident_note(payload)),200
        if path=="/api/v2/rules":return self.rules.save_rule(validate_rule(payload),source="custom"),201
        if path=="/api/v2/rules/toggle":return self.rules.set_enabled(str(payload.get("id","")),bool(payload.get("enabled"))),200
        if path=="/api/v2/rules/delete":
            rule_id=str(payload.get("id",""))
            try:self.rules.delete_rule(rule_id)
            except ValueError as error:raise ApiError(str(error),code="builtin_rule") from error
            return {"deleted":True,"id":rule_id},200
        if path=="/api/v2/detection-settings":return self.rules.save_settings(validate_detection_settings(payload)),200
        if path=="/api/v2/checkpoints/reset":
            channel=str(payload.get("channel",""))
            if channel not in ALLOWED_CHANNELS:raise ApiError("That Windows event channel is not allowed.")
            self.database.reset_checkpoint(channel);return {"reset":True,"channel":channel},200
        raise ApiError("API endpoint not found.",status=404,code="not_found")
    def _extract_nested_id(self,path,resource,action):
        try:return int(path.removeprefix(f"/api/v2/{resource}/").removesuffix(f"/{action}"))
        except ValueError as error:raise ApiError("Incident ID must be an integer.") from error
    def import_evtx(self,filename,stream,content_length,query):
        safe_name=validate_evtx_filename(filename)
        if content_length<=0 or content_length>self.settings.max_upload_bytes:raise ApiError("EVTX file is empty or exceeds the upload limit.",status=413,code="invalid_file_size")
        params=parse_qs(query);maximum=bounded_int(params.get("max",[self.settings.max_events])[0],"max",self.settings.max_events,maximum=self.settings.max_events)
        with tempfile.NamedTemporaryFile(suffix=".evtx",delete=False) as handle:
            temporary_path=Path(handle.name);remaining=content_length
            while remaining:
                chunk=stream.read(min(1024*1024,remaining))
                if not chunk:break
                handle.write(chunk);remaining-=len(chunk)
        try:events=parse_evtx(temporary_path,maximum)
        finally:temporary_path.unlink(missing_ok=True)
        return {"events":events,"sourceName":safe_name},200
