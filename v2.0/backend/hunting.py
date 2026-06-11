import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone

from .errors import ApiError

HUNTS = [
    {"id":"failed-login-hunt","title":"Failed login activity","description":"Find failed authentication events and repeated failures by source IP or user.","mitre":{"id":"T1110","name":"Brute Force","tactic":"Credential Access"},"severity":"Medium"},
    {"id":"powershell-abuse-hunt","title":"PowerShell abuse","description":"Find encoded, downloaded, bypassed, or obfuscated PowerShell activity.","mitre":{"id":"T1059.001","name":"PowerShell","tactic":"Execution"},"severity":"High"},
    {"id":"privilege-escalation-hunt","title":"Privilege escalation indicators","description":"Find special privileges, privileged group changes, services, tasks, and log clearing.","mitre":{"id":"T1068","name":"Exploitation for Privilege Escalation","tactic":"Privilege Escalation"},"severity":"High"},
    {"id":"account-creation-hunt","title":"Suspicious account creation","description":"Find new local or domain accounts and rapid privileged group membership changes.","mitre":{"id":"T1136","name":"Create Account","tactic":"Persistence"},"severity":"High"},
    {"id":"lateral-movement-hunt","title":"Lateral movement indicators","description":"Find remote interactive logons, admin shares, PsExec, WMI, WinRM, and remote services.","mitre":{"id":"T1021","name":"Remote Services","tactic":"Lateral Movement"},"severity":"High"},
    {"id":"reconnaissance-hunt","title":"Reconnaissance behaviour","description":"Find account, group, host, network, and domain discovery commands.","mitre":{"id":"T1087","name":"Account Discovery","tactic":"Discovery"},"severity":"Medium"},
]
HUNT_BY_ID={item["id"]:item for item in HUNTS}
IOC_TYPES={"ip","domain","hash","username","file_path"}
FIELDS=("timestamp","eventId","event_id","user","username","sourceIp","source_ip","destinationIp","destination_ip","host","status","process","parentProcess","command","message","logonType","destinationPort","targetFilename","registryKey","serviceName","group","privileges","hash")

def _text(event): return " ".join(str(event.get(field,"")) for field in FIELDS).lower()
def _event_id(event): return str(event.get("eventId") or event.get("event_id") or "")
def _timestamp(event):
    try: return datetime.fromisoformat(str(event.get("timestamp") or "").replace("Z","+00:00"))
    except ValueError: return datetime.min.replace(tzinfo=timezone.utc)
def _matches(hunt_id,event):
    event_id,text=_event_id(event),_text(event)
    if hunt_id=="failed-login-hunt": return event_id in {"4625","4771","4776"} or event.get("status")=="failed"
    if hunt_id=="powershell-abuse-hunt": return (event_id in {"4103","4104"} or "powershell" in text) and bool(re.search(r"-enc(?:odedcommand)?\b|frombase64string|downloadstring|invoke-expression|\biex\b|invoke-webrequest|\biwr\b|bypass|hidden|nop(?:rofile)?\b|amsi",text))
    if hunt_id=="privilege-escalation-hunt": return event_id in {"4672","4728","4732","4756","4698","7045","1102"} or bool(re.search(r"sedebugprivilege|seimpersonateprivilege|domain admins|administrators|scheduled task|new service|audit log was cleared",text))
    if hunt_id=="account-creation-hunt": return event_id in {"4720","4722","4728","4732","4756"} or bool(re.search(r"new account|user account (?:was )?created|net user .+ /add",text))
    if hunt_id=="lateral-movement-hunt": return (event_id=="4624" and str(event.get("logonType","")) in {"3","10"}) or bool(re.search(r"psexec|wmic|winrm|enter-pssession|invoke-command|admin\$|c\$|remote desktop|remote service|mstsc",text))
    if hunt_id=="reconnaissance-hunt": return bool(re.search(r"\bwhoami\b|\bnet user\b|\bnet group\b|\bnet localgroup\b|\bipconfig\b|\bsysteminfo\b|\btasklist\b|\bnltest\b|\bdsquery\b|\badfind\b|\bquser\b|\bqwinsta\b|\broute print\b|\barp -a\b",text))
    return False

def run_hunt(hunt_id,events):
    hunt=HUNT_BY_ID.get(hunt_id)
    if not hunt: raise ApiError("Threat hunt was not found.",status=404,code="hunt_not_found")
    if not isinstance(events,list): raise ApiError("Hunt events must be an array.",code="invalid_hunt")
    matches=sorted([event for event in events[:10000] if isinstance(event,dict) and _matches(hunt_id,event)],key=_timestamp)
    entities=sorted({str(value) for event in matches for value in (event.get("sourceIp") or event.get("source_ip"),event.get("user") or event.get("username"),event.get("host")) if value and str(value).lower()!="unknown"})
    return {"hunt":hunt,"matchCount":len(matches),"matches":matches,"entities":entities}

def normalize_ioc(ioc):
    if not isinstance(ioc,dict): raise ApiError("IOC must be an object.",code="invalid_ioc")
    ioc_type=str(ioc.get("type","")).strip().lower().replace("-","_"); value=str(ioc.get("value","")).strip()
    if ioc_type not in IOC_TYPES: raise ApiError("IOC type must be ip, domain, hash, username, or file_path.",code="invalid_ioc")
    if not value: raise ApiError("IOC value is required.",code="invalid_ioc")
    if ioc_type=="ip":
        try: value=str(ipaddress.ip_address(value))
        except ValueError as error: raise ApiError("IOC contains an invalid IP address.",code="invalid_ioc") from error
    elif ioc_type=="domain":
        value=value.lower().rstrip(".")
        if not re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}",value): raise ApiError("IOC contains an invalid domain.",code="invalid_ioc")
    elif ioc_type=="hash":
        value=re.sub(r"^(?:md5|sha1|sha256)=","",value,flags=re.I).lower()
        if not re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}",value): raise ApiError("IOC hash must be MD5, SHA-1, or SHA-256.",code="invalid_ioc")
    elif ioc_type in {"username","file_path"}: value=value.lower()
    return {"type":ioc_type,"value":value,"description":str(ioc.get("description","")).strip()[:500],"enabled":bool(ioc.get("enabled",True))}

def _values(event):
    text=_text(event); hashes=set(re.findall(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b",text)); domains=set(re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b",text))
    return {"ip":{str(v).lower() for v in (event.get("sourceIp"),event.get("source_ip"),event.get("destinationIp"),event.get("destination_ip")) if v},"domain":{v.lower().rstrip(".") for v in domains},"hash":{v.lower() for v in hashes}|{v.lower() for v in re.split(r"[,;\s]+",str(event.get("hash",""))) if v},"username":{str(v).lower() for v in (event.get("user"),event.get("username")) if v},"file_path":{str(v).lower() for v in (event.get("process"),event.get("parentProcess"),event.get("targetFilename")) if v}}

def match_iocs(events,iocs):
    if not isinstance(events,list): raise ApiError("IOC match events must be an array.",code="invalid_ioc_match")
    matches=[]
    for event in events[:10000]:
        if not isinstance(event,dict): continue
        values=_values(event)
        for ioc in [item for item in iocs if item.get("enabled")]:
            candidate=ioc["value"].lower(); matched=candidate in values.get(ioc["type"],set())
            if ioc["type"]=="file_path": matched=any(candidate==value or candidate in value for value in values["file_path"])
            if matched: matches.append({"ioc":ioc,"event":event,"matchedField":ioc["type"]})
    fingerprint=hashlib.sha256(json.dumps(matches,sort_keys=True,ensure_ascii=True).encode()).hexdigest()
    return {"matchCount":len(matches),"matches":matches,"fingerprint":fingerprint}

def attack_heatmap(alerts):
    counts={}
    for alert in alerts if isinstance(alerts,list) else []:
        if not isinstance(alert,dict): continue
        mitre=alert.get("mitre") if isinstance(alert.get("mitre"),dict) else {}; technique_id=str(mitre.get("id") or alert.get("mitreId") or "").strip()
        if not technique_id: continue
        item=counts.setdefault(technique_id,{"id":technique_id,"name":mitre.get("name") or "Mapped technique","tactic":mitre.get("tactic") or "Unknown","count":0}); item["count"]+=1
    maximum=max((item["count"] for item in counts.values()),default=0)
    return [{**item,"intensity":round(item["count"]/maximum,3) if maximum else 0} for item in sorted(counts.values(),key=lambda value:(-value["count"],value["id"]))]

def investigation_timeline(incident):
    payload=incident.get("payload") if isinstance(incident.get("payload"),dict) else {}; events=list(payload.get("evidence") or [])
    for alert in payload.get("alerts") or [payload.get("alert")]:
        if isinstance(alert,dict): events.extend(alert.get("events") or [])
    unique={json.dumps(event,sort_keys=True,ensure_ascii=True):event for event in events if isinstance(event,dict)}
    return [{"timestamp":e.get("timestamp"),"eventId":e.get("eventId") or e.get("event_id"),"user":e.get("user") or e.get("username"),"sourceIp":e.get("sourceIp") or e.get("source_ip"),"host":e.get("host"),"process":e.get("process"),"command":e.get("command"),"message":e.get("message"),"status":e.get("status")} for e in sorted(unique.values(),key=_timestamp)]
