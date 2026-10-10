import unittest
from unittest.mock import patch
import test_assessment_run

class RunFailureTests(unittest.TestCase):
    def test_transport_error_is_partial_failure(self):
        from yf_tools.assessment_run import run
        policy=test_assessment_run.RunTests().policy()
        with patch('yf_tools.assessment_run.inspect', return_value={'status':'transport_error'}):
            result=run(policy,['http://127.0.0.1/'])
        self.assertEqual(result['status'],'completed_with_errors')
        self.assertEqual(result['failed_count'],1)

    def test_backpressure_stops_remaining_requests(self):
        from yf_tools.assessment_run import run
        with patch('yf_tools.assessment_run.inspect', return_value={'status':'observed','http_status':429}) as probe:
            result=run(test_assessment_run.RunTests().policy(),['http://127.0.0.1/']*2)
        self.assertEqual(result['status'],'paused_backpressure')
        self.assertEqual(result['unprocessed_count'],1)
        probe.assert_called_once()
