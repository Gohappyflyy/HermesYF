import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(429 if self.path == '/busy' else (302 if self.path == '/redirect' else 200))
        self.send_header('Location', 'https://outside.invalid/?token=secret')
        self.send_header('Set-Cookie', 'session=SECRET')
        self.send_header('Server', 'fixture')
        self.end_headers()
    def log_message(self, *args):
        pass

class HTTPBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join()
    def policy(self):
        return {'targets':['127.0.0.1'], 'exclude':[], 'allowed_tests':['http_baseline'],
                'requests_per_second':1, 'http_ports':[self.port]}
    def test_cli_end_to_end_json_report(self):
        from datetime import datetime, timezone, timedelta
        from pathlib import Path
        import tempfile, subprocess, sys, json
        p=self.policy();now=datetime.now(timezone.utc)
        p.update(http_paths=['/'], max_targets=1,
                 window_start=(now-timedelta(minutes=1)).isoformat(),
                 window_end=(now+timedelta(minutes=1)).isoformat())
        with tempfile.TemporaryDirectory() as directory:
            policy=Path(directory)/'policy.json';targets=Path(directory)/'targets.json'
            policy.write_text(json.dumps(p))
            targets.write_text(json.dumps([f'http://127.0.0.1:{self.port}/']))
            result=subprocess.run([sys.executable,'-m','yf_tools.assessment_run',
                                   '--policy',str(policy),'--targets',str(targets)],
                                  cwd=Path(__file__).resolve().parents[1],
                                  capture_output=True,text=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr)
        report=json.loads(result.stdout)
        self.assertEqual(report['results'][0]['http_status'],200)
        self.assertEqual(report['status'],'completed')
        self.assertNotIn('SECRET',result.stdout)

    def test_real_backpressure_stops_batch(self):
        from yf_tools.assessment_run import run
        from datetime import datetime, timezone, timedelta
        p=self.policy();now=datetime.now(timezone.utc)
        p.update(http_paths=['/busy','/'], max_targets=2,
                 window_start=(now-timedelta(minutes=1)).isoformat(),
                 window_end=(now+timedelta(minutes=1)).isoformat())
        result=run(p,[f'http://127.0.0.1:{self.port}/busy',f'http://127.0.0.1:{self.port}/'])
        self.assertEqual(result['status'],'paused_backpressure')
        self.assertEqual(len(result['results']),1)
        self.assertEqual(result['unprocessed_count'],1)

    def test_batch_runner_real_requests(self):
        from yf_tools.assessment_run import run
        from datetime import datetime, timezone, timedelta
        p=self.policy();now=datetime.now(timezone.utc)
        p.update(http_paths=['/','/redirect'], max_targets=2,
                 window_start=(now-timedelta(minutes=1)).isoformat(),
                 window_end=(now+timedelta(minutes=1)).isoformat())
        urls=[f'http://127.0.0.1:{self.port}/',f'http://127.0.0.1:{self.port}/redirect']
        result=run(p,urls)
        self.assertEqual(result['status'],'completed')
        self.assertEqual([r['http_status'] for r in result['results']],[200,302])

    def test_actual_head_and_sensitive_headers_omitted(self):
        from yf_tools.http_baseline import inspect
        import json
        result = inspect(self.policy(), f'http://127.0.0.1:{self.port}/')
        self.assertEqual(result['http_status'], 200)
        self.assertEqual(result['method'], 'HEAD')
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('secret', json.dumps(result))
    def test_redirect_not_followed(self):
        from yf_tools.http_baseline import inspect
        result = inspect(self.policy(), f'http://127.0.0.1:{self.port}/redirect')
        self.assertEqual(result['http_status'], 302)
        self.assertFalse(result['redirect_followed'])
    def test_unapproved_port_no_request(self):
        from yf_tools.http_baseline import inspect
        from yf_tools.assessment_plan import PlanError
        p=self.policy(); p['http_ports']=[1]
        with patch('urllib.request.OpenerDirector.open') as send:
            with self.assertRaises(PlanError): inspect(p, f'http://127.0.0.1:{self.port}/')
            send.assert_not_called()
    def test_dns_hosts_not_yet_supported(self):
        from yf_tools.http_baseline import inspect
        from yf_tools.assessment_plan import PlanError
        p=self.policy();p['targets']=['example.test'];p['http_ports']=[80]
        with self.assertRaises(PlanError): inspect(p, 'http://example.test/')
    def test_required_test_authorization(self):
        from yf_tools.http_baseline import inspect
        from yf_tools.assessment_plan import PlanError
        p=self.policy();p['allowed_tests']=['port_scan']
        with self.assertRaises(PlanError): inspect(p, f'http://127.0.0.1:{self.port}/')
    def test_query_and_credentials_rejected(self):
        from yf_tools.http_baseline import inspect
        from yf_tools.assessment_plan import PlanError
        for url in [f'http://127.0.0.1:{self.port}/?token=x', f'http://u:p@127.0.0.1:{self.port}/']:
            with self.assertRaises(PlanError): inspect(self.policy(), url)
