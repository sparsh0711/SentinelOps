import base64
import unittest
from backend.hunting import attack_heatmap, investigation_timeline, match_iocs, normalize_ioc, run_hunt
from backend.reports import report_payload
from backend.sigma import convert_sigma
class HuntingTests(unittest.TestCase):
 def test_hunts(self):
  self.assertEqual(run_hunt("failed-login-hunt",[{"eventId":"4625","status":"failed"}])["matchCount"],1)
  self.assertEqual(run_hunt("powershell-abuse-hunt",[{"eventId":"4104","command":"powershell -EncodedCommand AAAA"}])["matchCount"],1)
 def test_iocs(self):
  i=normalize_ioc({"type":"domain","value":"Bad.Example."});r=match_iocs([{"message":"Connected to bad.example"}],[{**i,"id":1,"enabled":True}]);self.assertEqual(r["matchCount"],1)
 def test_sigma(self):
  r=convert_sigma({"title":"Test","id":"test","level":"high","detection":{"selection":{"EventID":4625},"condition":"selection"},"tags":["attack.t1110"]});self.assertEqual(r["mitre"]["id"],"T1110")
 def test_heatmap_timeline_reports(self):
  self.assertEqual(attack_heatmap([{"mitre":{"id":"T1110"}},{"mitre":{"id":"T1110"}}])[0]["count"],2);i={"id":1,"title":"Test","status":"New","severity":"High","risk_score":90,"owner":"","source_name":"test","payload":{"evidence":[{"timestamp":"2026-01-01T00:00:00Z","eventId":"4625"}]},"summaries":[]};self.assertEqual(investigation_timeline(i)[0]["eventId"],"4625");self.assertTrue(base64.b64decode(report_payload(i,"pdf")["contentBase64"]).startswith(b"%PDF-1.4"))
