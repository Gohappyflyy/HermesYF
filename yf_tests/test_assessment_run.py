import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

class RunTests(unittest.TestCase):
    def policy(self):
        now=datetime.now(timezone.utc)
        return {'targets':['127.0.0.1'],'exclude':[], 'allowed_tests':['http_baseline'], 'http_ports':[80], 'requests_per_second':2, 'http_paths':['/'], 'window_start':(now-timedelta(minutes=1)).isoformat(), 'window_end':(now+timedelta(minutes=1)).isoformat(), 'max_targets':2}
    def test_runs_approved_task(self):
        from yf_tools.assessment_run import run
        with patch('yf_tools.http_baseline.inspect', return_value={'status':'observed','http_status':200}) as request:
            r=run(self.policy(),['http://127.0.0.1/'])
        self.assertEqual(r['results'][0]['status'],'observed')
        request.assert_called_once()
    def test_all_targets_prevalidated(self):
        from yf_tools.assessment_run import run
        from yf_tools.assessment_plan import PlanError
        with patch('yf_tools.http_baseline.inspect') as request:
            with self.assertRaises(PlanError):run(self.policy(),['http://127.0.0.1/','http://192.0.2.1/'])
            request.assert_not_called()
    def test_expired_window(self):
        from yf_tools.assessment_run import run
        from yf_tools.assessment_plan import PlanError
        p=self.policy();p['window_end']='2000-01-01T00:00:00+00:00'
        with self.assertRaises(PlanError):run(p,['http://127.0.0.1/'])
    def test_path_not_authorized(self):
        from yf_tools.assessment_run import run
        from yf_tools.assessment_plan import PlanError
        with self.assertRaises(PlanError):run(self.policy(),['http://127.0.0.1/admin'])
    def test_unsupported_tasks_not_silently_executed(self):
        from yf_tools.assessment_run import run
        # Old behavior: runner checked allowed_tests == ['http_baseline']
        # New behavior: with backward compat, defaults to http_baseline only
        # If we explicitly request 'fuzz' task, it should fail as unsupported
        p=self.policy();p['allowed_tests']=['http_baseline', 'fuzz']
        with self.assertRaises(ValueError):run(p,['http://127.0.0.1/'], tasks=['fuzz'])
    def test_target_limit(self):
        from yf_tools.assessment_run import run
        from yf_tools.assessment_plan import PlanError
        p=self.policy();p['max_targets']=1
        with self.assertRaises(PlanError):run(p,['http://127.0.0.1/']*2)
    def test_rate_scheduling(self):
        from yf_tools.assessment_run import run
        with patch('yf_tools.http_baseline.inspect',return_value={'status':'observed'}), patch('yf_tools.assessment_run.time.monotonic',side_effect=[0,0.1]), patch('yf_tools.assessment_run.time.sleep') as sleep:
            run(self.policy(),['http://127.0.0.1/']*2)
        sleep.assert_called_once_with(0.4)
