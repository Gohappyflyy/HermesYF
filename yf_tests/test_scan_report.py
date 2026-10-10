import unittest

class ScanReportTests(unittest.TestCase):
    def finding(self):
        return {'template-id':'test-id','matched-at':'https://example.test/path?token=secret', 'info':{'name':'Candidate','severity':'high'},'request':'SECRET','response':'SECRET'}

    def test_raw_evidence_and_query_not_retained(self):
        from yf_tools.scan_report import summarize
        import json
        result=summarize([self.finding()])
        self.assertNotIn('SECRET',json.dumps(result))
        self.assertNotIn('secret',json.dumps(result))
        self.assertEqual(result['findings'][0]['target'],'https://example.test/path')

    def test_duplicate_is_counted(self):
        from yf_tools.scan_report import summarize
        result=summarize([self.finding(),self.finding()])
        self.assertEqual(len(result['findings']),1)
        self.assertEqual(result['findings'][0]['occurrences'],2)

    def test_hits_never_become_verified(self):
        from yf_tools.scan_report import summarize
        self.assertEqual(summarize([self.finding()])['findings'][0]['verification'],'unverified')

    def test_unknown_severity_normalized(self):
        from yf_tools.scan_report import summarize
        entry=self.finding();entry['info']['severity']='whatever'
        self.assertEqual(summarize([entry])['findings'][0]['severity'],'unknown')

    def test_invalid_rows_fail_explicitly(self):
        from yf_tools.scan_report import summarize, ReportError
        for entry in [None,{}, {'template-id':'x','matched-at':'https://user:pass@example.test'}]:
            with self.subTest(entry=entry), self.assertRaises(ReportError): summarize([entry])

    def test_deterministic_order(self):
        from yf_tools.scan_report import summarize
        a=self.finding();b=self.finding();b['template-id']='another'
        self.assertEqual(summarize([a,b]),summarize([b,a]))
