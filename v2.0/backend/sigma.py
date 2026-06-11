import json
import re

from .errors import ApiError
from .validation import validate_rule

FIELD_MAP={"eventid":"eventId","event_id":"eventId","image":"process","parentimage":"parentProcess","commandline":"command","scriptblocktext":"command","targetusername":"user","subjectusername":"user","ipaddress":"sourceIp","sourceip":"sourceIp","destinationip":"destinationIp","destinationport":"destinationPort","targetfilename":"targetFilename","targetobject":"registryKey","servicename":"serviceName","logontype":"logonType","message":"message"}
def _scalar(value):
    value=value.strip()
    if not value:return ""
    if value[0:1] in {'"',"'"} and value[-1:]==value[0]:return value[1:-1]
    if value.lower() in {"true","false"}:return value.lower()=="true"
    if re.fullmatch(r"-?\d+",value):return int(value)
    if value.startswith("[") and value.endswith("]"):return [_scalar(item) for item in value[1:-1].split(",") if item.strip()]
    return value
def _simple_yaml(text):
    result={}; stack=[(-1,result)]; lines=text.splitlines()
    for index,raw_line in enumerate(lines):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):continue
        indent=len(raw_line)-len(raw_line.lstrip(" "));line=raw_line.strip()
        if line.startswith("- "):
            parent=stack[-1][1]
            if not isinstance(parent,list):raise ApiError("Unsupported Sigma YAML list structure.",code="invalid_sigma")
            parent.append(_scalar(line[2:]));continue
        if ":" not in line:continue
        key,raw_value=line.split(":",1)
        while stack[-1][0]>=indent:stack.pop()
        parent=stack[-1][1];value=raw_value.strip()
        if value:parent[key.strip()]=_scalar(value);continue
        container={}
        for next_line in lines[index+1:]:
            if not next_line.strip() or next_line.lstrip().startswith("#"):continue
            next_indent=len(next_line)-len(next_line.lstrip(" "))
            if next_indent<=indent:break
            if next_line.strip().startswith("- "):container=[]
            break
        parent[key.strip()]=container;stack.append((indent,container))
    return result
def parse_sigma(value):
    if isinstance(value,dict):return value
    text=str(value or "").strip()
    if not text:raise ApiError("Sigma rule text is required.",code="invalid_sigma")
    try:return json.loads(text)
    except json.JSONDecodeError:return _simple_yaml(text)
def _conditions(selection):
    conditions=[]
    if not isinstance(selection,dict):return conditions
    for raw_field,raw_value in selection.items():
        parts=str(raw_field).split("|");field=FIELD_MAP.get(parts[0].lower(),parts[0]);modifier=parts[1].lower() if len(parts)>1 else "";values=raw_value if isinstance(raw_value,list) else [raw_value]
        if modifier=="contains":conditions.append({"field":field,"operator":"regex","value":"|".join(re.escape(str(value)) for value in values)})
        elif modifier in {"startswith","endswith"}:
            fragments=[]
            for value in values:
                escaped=re.escape(str(value));fragments.append(f"^{escaped}" if modifier=="startswith" else f"{escaped}$")
            conditions.append({"field":field,"operator":"regex","value":"|".join(fragments)})
        elif len(values)>1:conditions.append({"field":field,"operator":"in","value":values})
        else:conditions.append({"field":field,"operator":"equals","value":values[0]})
    return conditions
def convert_sigma(value):
    sigma=parse_sigma(value);detection=sigma.get("detection")
    if not isinstance(detection,dict):raise ApiError("Sigma detection section is required.",code="invalid_sigma")
    condition_text=str(detection.get("condition","")).strip();names=[name for name in detection if name!="condition" and isinstance(detection[name],dict)]
    if not names:raise ApiError("Sigma rule needs at least one selection.",code="invalid_sigma")
    selected=[name for name in names if not condition_text or re.search(rf"\b{re.escape(name)}\b",condition_text)] or names[:1];mode="any" if " or " in condition_text.lower() or "1 of" in condition_text.lower() else "all";conditions=[]
    for name in selected:conditions.extend(_conditions(detection[name]))
    if not conditions:raise ApiError("Sigma selections could not be converted.",code="invalid_sigma")
    tags=sigma.get("tags") if isinstance(sigma.get("tags"),list) else [];technique=next((str(tag).split("attack.",1)[1].upper() for tag in tags if str(tag).lower().startswith("attack.t")),"T1059");rule_id=str(sigma.get("id") or re.sub(r"[^a-z0-9]+","-",str(sigma.get("title","sigma-rule")).lower())).strip("-")
    return validate_rule({"id":f"sigma-{rule_id}"[:120],"title":str(sigma.get("title") or "Imported Sigma rule")[:200],"description":str(sigma.get("description") or "Imported from a simple Sigma rule.")[:1000],"level":str(sigma.get("level") or "Medium").title(),"enabled":True,"confidence":70,"status":sigma.get("status") or "experimental","logsource":sigma.get("logsource") or {},"match":{mode:conditions},"mitre":{"id":technique,"name":"Imported Sigma mapping","tactic":"Imported"},"tags":tags,"falsepositives":sigma.get("falsepositives") or [],"sigmaSource":sigma})
