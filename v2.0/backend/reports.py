import base64
import html
import json
import textwrap

from .hunting import investigation_timeline

def _escape(value):return html.escape(str(value or ""))
def build_html_report(incident):
    summary=(incident.get("summaries") or [{}])[0];timeline=investigation_timeline(incident);techniques=summary.get("mitreTechniques") or []
    sections=(("Executive Summary",summary.get("executiveSummary") or "No incident summary has been generated."),("Technical Investigation Summary",summary.get("technicalSummary") or "No technical summary is available."),("Risk Explanation",summary.get("riskExplanation") or f"Stored risk score: {incident.get('risk_score',0)}/100."))
    section_html="".join(f"<section><h2>{_escape(title)}</h2><p>{_escape(body)}</p></section>" for title,body in sections)
    lists=(("Suspicious Behaviour",summary.get("suspiciousBehaviour") or []),("Investigation Steps",summary.get("investigationSteps") or []),("Containment and Remediation",summary.get("containmentActions") or []),("Evidence Limitations",summary.get("evidenceLimitations") or []))
    list_html="".join(f"<section><h2>{_escape(title)}</h2><ul>{''.join(f'<li>{_escape(item)}</li>' for item in items) or '<li>None recorded.</li>'}</ul></section>" for title,items in lists)
    technique_html="".join(f"<li><strong>{_escape(item.get('id'))} {_escape(item.get('name'))}</strong>: {_escape(item.get('evidence'))}</li>" for item in techniques) or "<li>No MITRE ATT&CK mapping was present in the evidence.</li>"
    timeline_html="".join("<tr>"+f"<td>{_escape(item.get('timestamp'))}</td><td>{_escape(item.get('eventId'))}</td><td>{_escape(item.get('user'))}</td><td>{_escape(item.get('sourceIp'))}</td><td>{_escape(item.get('host'))}</td><td>{_escape(item.get('message') or item.get('command'))}</td></tr>" for item in timeline) or '<tr><td colspan="6">No related events were stored.</td></tr>'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>SentinelOps Incident #{incident['id']}</title><style>body{{font:14px/1.55 Arial,sans-serif;color:#182230;max-width:1000px;margin:40px auto;padding:0 24px}}h1{{color:#0b5278}}h2{{border-bottom:1px solid #ccd8e0;padding-bottom:5px;margin-top:28px}}.meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;background:#eef5f8;padding:14px}}table{{width:100%;border-collapse:collapse;font-size:12px}}th,td{{border:1px solid #ccd8e0;padding:7px;text-align:left;vertical-align:top}}</style></head><body><h1>SentinelOps Incident Report</h1><div class="meta"><span><strong>Incident</strong><br>#{incident['id']} {_escape(incident.get('title'))}</span><span><strong>Status</strong><br>{_escape(incident.get('status'))}</span><span><strong>Severity / Risk</strong><br>{_escape(incident.get('severity'))} / {_escape(incident.get('risk_score'))}</span><span><strong>Owner</strong><br>{_escape(incident.get('owner') or 'Unassigned')}</span><span><strong>Source</strong><br>{_escape(incident.get('source_name'))}</span><span><strong>Evidence fingerprint</strong><br>{_escape(summary.get('evidenceHash') or 'Not generated')}</span></div>{section_html}<section><h2>MITRE ATT&CK</h2><ul>{technique_html}</ul></section>{list_html}<section><h2>Investigation Timeline</h2><table><thead><tr><th>Time</th><th>Event</th><th>User</th><th>Source IP</th><th>Host</th><th>Details</th></tr></thead><tbody>{timeline_html}</tbody></table></section><p>Generated locally by SentinelOps.</p></body></html>'''
def _pdf_escape(value):return str(value).replace("\\","\\\\").replace("(","\\(").replace(")","\\)")
def build_pdf_report(incident):
    summary=(incident.get("summaries") or [{}])[0];timeline=investigation_timeline(incident);lines=["SentinelOps Incident Report",f"Incident #{incident['id']}: {incident.get('title','')}",f"Status: {incident.get('status','')}   Severity: {incident.get('severity','')}   Risk: {incident.get('risk_score',0)}/100",f"Owner: {incident.get('owner') or 'Unassigned'}   Source: {incident.get('source_name','')}","","Executive Summary",summary.get("executiveSummary") or "No incident summary has been generated.","","Technical Investigation Summary",summary.get("technicalSummary") or "No technical summary is available.","","Risk Explanation",summary.get("riskExplanation") or f"Stored risk score: {incident.get('risk_score',0)}/100.","","Investigation Steps",*[f"- {item}" for item in summary.get("investigationSteps") or ["None recorded."]],"","Containment and Remediation",*[f"- {item}" for item in summary.get("containmentActions") or ["None recorded."]],"","Investigation Timeline",*[f"{item.get('timestamp','')} | {item.get('eventId','')} | {item.get('user','')} | {item.get('sourceIp','')} | {item.get('message') or item.get('command') or ''}" for item in timeline[:60]]]
    wrapped=[]
    for line in lines:wrapped.extend(textwrap.wrap(str(line),width=95) or [""])
    chunks=[wrapped[i:i+48] for i in range(0,len(wrapped),48)] or [[]];objects=[];page_ids=[];font_id=3+len(chunks)*2
    for index,page_lines in enumerate(chunks):
        page_id=3+index*2;content_id=page_id+1;page_ids.append(page_id);stream=["BT","/F1 10 Tf","48 760 Td","13 TL"]+[f"({_pdf_escape(line)}) Tj T*" for line in page_lines]+["ET"];encoded="\n".join(stream).encode("latin-1",errors="replace");objects.append((page_id,f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>".encode()));objects.append((content_id,f"<< /Length {len(encoded)} >>\nstream\n".encode()+encoded+b"\nendstream"))
    objects.extend([(1,b"<< /Type /Catalog /Pages 2 0 R >>"),(2,f"<< /Type /Pages /Count {len(page_ids)} /Kids [{' '.join(f'{item} 0 R' for item in page_ids)}] >>".encode()),(font_id,b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")]);objects.sort();output=bytearray(b"%PDF-1.4\n");offsets={0:0}
    for object_id,body in objects:offsets[object_id]=len(output);output.extend(f"{object_id} 0 obj\n".encode()+body+b"\nendobj\n")
    xref=len(output);size=max(offsets)+1;output.extend(f"xref\n0 {size}\n".encode());output.extend(b"0000000000 65535 f \n")
    for object_id in range(1,size):output.extend(f"{offsets.get(object_id,0):010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {size} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode());return bytes(output)
def report_payload(incident,format_name):
    safe="".join(c if c.isalnum() else "-" for c in incident["title"]).strip("-").lower()
    if format_name=="html":content=build_html_report(incident).encode();media_type="text/html";extension="html"
    else:content=build_pdf_report(incident);media_type="application/pdf";extension="pdf"
    return {"filename":f"sentinelops-incident-{incident['id']}-{safe[:50]}.{extension}","mediaType":media_type,"contentBase64":base64.b64encode(content).decode(),"metadata":json.dumps({"incidentId":incident["id"],"format":extension})}
