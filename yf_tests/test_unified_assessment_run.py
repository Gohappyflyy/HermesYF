"""Test unified assessment runner integrating HTTP/Nmap/Nuclei with strict TDD.

Tests cover:
- Policy validation for multiple task types
- Sequential execution with shared rate limiting
- Mixed results handling
- Error isolation (errors in one type don't stop others)
- Aggregate status calculation
- Task type discriminator in results
"""
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
import json


class UnifiedAssessmentRunTests(unittest.TestCase):
    """Test unified assessment runner with multiple task types"""
    
    def base_policy(self):
        """Base policy with common fields"""
        now = datetime.now(timezone.utc)
        return {
            'targets': ['127.0.0.1'],
            'exclude': [],
            'requests_per_second': 2,
            'window_start': (now - timedelta(minutes=1)).isoformat(),
            'window_end': (now + timedelta(minutes=1)).isoformat(),
            'max_targets': 2
        }
    
    def test_empty_tasks_rejected(self):
        """Empty tasks list should be rejected"""
        from yf_tools.assessment_run import run
        from yf_tools.assessment_plan import PlanError
        policy = self.base_policy()
        policy['allowed_tests'] = []
        with self.assertRaises(PlanError):
            run(policy, ['http://127.0.0.1/'], tasks=[])
    
    def test_invalid_task_type_rejected(self):
        """Unknown task types should be rejected"""
        from yf_tools.assessment_run import run
        from yf_tools.assessment_plan import PlanError
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline']
        with self.assertRaises(ValueError) as ctx:
            run(policy, ['http://127.0.0.1/'], tasks=['invalid_task'])
        self.assertIn('invalid_task', str(ctx.exception))
    
    def test_http_baseline_requires_http_ports_and_paths(self):
        """http_baseline task requires http_ports and http_paths in policy"""
        from yf_tools.assessment_run import run
        from yf_tools.assessment_plan import PlanError
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline']
        # Missing http_ports
        with self.assertRaises(PlanError):
            run(policy, ['http://127.0.0.1/'], tasks=['http_baseline'])
        
        # Missing http_paths
        policy['http_ports'] = [80]
        with self.assertRaises(PlanError):
            run(policy, ['http://127.0.0.1/'], tasks=['http_baseline'])
    
    def test_port_scan_requires_port_scan_ports(self):
        """port_scan task requires port_scan_ports in policy"""
        from yf_tools.assessment_run import run
        from yf_tools.assessment_plan import PlanError
        policy = self.base_policy()
        policy['allowed_tests'] = ['port_scan']
        with self.assertRaises(PlanError):
            run(policy, ['127.0.0.1'], tasks=['port_scan'])
    
    def test_template_scan_requires_nuclei_fields(self):
        """template_scan requires nuclei_templates and approved_template_dir"""
        from yf_tools.assessment_run import run
        from yf_tools.assessment_plan import PlanError
        policy = self.base_policy()
        policy['allowed_tests'] = ['template_scan']
        # Missing nuclei_templates
        with self.assertRaises(PlanError):
            run(policy, ['http://127.0.0.1/'], tasks=['template_scan'])
        
        # Missing approved_template_dir
        policy['nuclei_templates'] = ['test.yaml']
        with self.assertRaises(PlanError):
            run(policy, ['http://127.0.0.1/'], tasks=['template_scan'])
    
    def test_single_http_baseline_task(self):
        """Single HTTP baseline task executes correctly"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        
        with patch('yf_tools.http_baseline.inspect') as mock_http:
            mock_http.return_value = {'kind': 'http_baseline', 'status': 'observed', 'http_status': 200}
            result = run(policy, ['http://127.0.0.1/'], tasks=['http_baseline'])
        
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(result['results']), 1)
        self.assertEqual(result['results'][0]['task_type'], 'http_baseline')
        self.assertEqual(result['results'][0]['status'], 'observed')
        self.assertEqual(result['task_counts']['http_baseline'], 1)
    
    def test_single_port_scan_task(self):
        """Single port scan task executes correctly"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['port_scan']
        policy['port_scan_ports'] = [22, 80]
        
        with patch('yf_tools.nmap_baseline.scan') as mock_nmap:
            mock_nmap.return_value = {'kind': 'port_scan', 'status': 'completed', 'ports': []}
            result = run(policy, ['127.0.0.1'], tasks=['port_scan'])
        
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(result['results']), 1)
        self.assertEqual(result['results'][0]['task_type'], 'port_scan')
        self.assertEqual(result['task_counts']['port_scan'], 1)
    
    def test_single_template_scan_task(self):
        """Single template scan task executes correctly"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['template_scan']
        policy['nuclei_templates'] = ['test.yaml']
        policy['approved_template_dir'] = '/tmp/templates'
        
        with patch('yf_tools.nuclei_scan.execute_scan') as mock_nuclei:
            mock_nuclei.return_value = {'kind': 'nuclei_template_scan', 'status': 'completed', 'matches': []}
            result = run(policy, ['http://127.0.0.1/'], tasks=['template_scan'])
        
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(result['results']), 1)
        self.assertEqual(result['results'][0]['task_type'], 'template_scan')
        self.assertEqual(result['task_counts']['template_scan'], 1)
    
    def test_multiple_tasks_executed_sequentially(self):
        """Multiple task types execute in sequence for same target"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline', 'port_scan', 'template_scan']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        policy['port_scan_ports'] = [80]
        policy['nuclei_templates'] = ['test.yaml']
        policy['approved_template_dir'] = '/tmp/templates'
        
        with patch('yf_tools.http_baseline.inspect') as mock_http, \
             patch('yf_tools.nmap_baseline.scan') as mock_nmap, \
             patch('yf_tools.nuclei_scan.execute_scan') as mock_nuclei:
            
            mock_http.return_value = {'kind': 'http_baseline', 'status': 'observed'}
            mock_nmap.return_value = {'kind': 'port_scan', 'status': 'completed', 'ports': []}
            mock_nuclei.return_value = {'kind': 'nuclei_template_scan', 'status': 'completed', 'matches': []}
            
            result = run(policy, ['http://127.0.0.1/'], 
                        tasks=['http_baseline', 'port_scan', 'template_scan'])
        
        # Should have 3 results (one per task type)
        self.assertEqual(len(result['results']), 3)
        task_types = [r['task_type'] for r in result['results']]
        self.assertEqual(task_types, ['http_baseline', 'port_scan', 'template_scan'])
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['task_counts']['http_baseline'], 1)
        self.assertEqual(result['task_counts']['port_scan'], 1)
        self.assertEqual(result['task_counts']['template_scan'], 1)
    
    def test_multiple_targets_multiple_tasks(self):
        """Multiple targets with multiple tasks execute correctly"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline', 'port_scan']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        policy['port_scan_ports'] = [80]
        
        with patch('yf_tools.http_baseline.inspect') as mock_http, \
             patch('yf_tools.nmap_baseline.scan') as mock_nmap:
            
            mock_http.return_value = {'kind': 'http_baseline', 'status': 'observed'}
            mock_nmap.return_value = {'kind': 'port_scan', 'status': 'completed', 'ports': []}
            
            result = run(policy, ['http://127.0.0.1/', 'http://127.0.0.1:80/'], 
                        tasks=['http_baseline', 'port_scan'])
        
        # 2 targets × 2 tasks = 4 results
        self.assertEqual(len(result['results']), 4)
        self.assertEqual(result['task_counts']['http_baseline'], 2)
        self.assertEqual(result['task_counts']['port_scan'], 2)
    
    def test_rate_limiting_across_all_tasks(self):
        """Rate limiting applies across all task types"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline', 'port_scan']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        policy['port_scan_ports'] = [80]
        policy['requests_per_second'] = 2  # 0.5s interval
        
        with patch('yf_tools.http_baseline.inspect') as mock_http, \
             patch('yf_tools.nmap_baseline.scan') as mock_nmap, \
             patch('yf_tools.assessment_run.time.monotonic', side_effect=[0, 0.1, 0.2, 0.3]), \
             patch('yf_tools.assessment_run.time.sleep') as mock_sleep:
            
            mock_http.return_value = {'kind': 'http_baseline', 'status': 'observed'}
            mock_nmap.return_value = {'kind': 'port_scan', 'status': 'completed', 'ports': []}
            
            run(policy, ['http://127.0.0.1/'], tasks=['http_baseline', 'port_scan'])
        
        # Should sleep between tasks
        self.assertTrue(mock_sleep.called)
    
    def test_error_in_one_task_doesnt_stop_others(self):
        """Error in one task type doesn't prevent other tasks from running"""
        from yf_tools.assessment_run import run
        from yf_tools.assessment_plan import PlanError
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline', 'port_scan', 'template_scan']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        policy['port_scan_ports'] = [80]
        policy['nuclei_templates'] = ['test.yaml']
        policy['approved_template_dir'] = '/tmp/templates'
        
        with patch('yf_tools.http_baseline.inspect') as mock_http, \
             patch('yf_tools.nmap_baseline.scan') as mock_nmap, \
             patch('yf_tools.nuclei_scan.execute_scan') as mock_nuclei:
            
            # Port scan fails with PlanError
            mock_http.return_value = {'kind': 'http_baseline', 'status': 'observed'}
            mock_nmap.side_effect = PlanError('port scan error')
            mock_nuclei.return_value = {'kind': 'nuclei_template_scan', 'status': 'completed', 'matches': []}
            
            result = run(policy, ['http://127.0.0.1/'], 
                        tasks=['http_baseline', 'port_scan', 'template_scan'])
        
        # Should have 3 results, port_scan marked as error
        self.assertEqual(len(result['results']), 3)
        self.assertEqual(result['results'][0]['task_type'], 'http_baseline')
        self.assertEqual(result['results'][0]['status'], 'observed')
        self.assertEqual(result['results'][1]['task_type'], 'port_scan')
        self.assertEqual(result['results'][1]['status'], 'task_error')
        self.assertEqual(result['results'][2]['task_type'], 'template_scan')
        self.assertEqual(result['results'][2]['status'], 'completed')
        self.assertEqual(result['status'], 'completed_with_errors')
    
    def test_backpressure_stops_remaining_tasks(self):
        """429/503 in any task stops all remaining tasks for that target"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline', 'port_scan']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        policy['port_scan_ports'] = [80]
        
        with patch('yf_tools.http_baseline.inspect') as mock_http, \
             patch('yf_tools.nmap_baseline.scan') as mock_nmap:
            
            # HTTP returns 429
            mock_http.return_value = {'kind': 'http_baseline', 'status': 'observed', 'http_status': 429}
            
            result = run(policy, ['http://127.0.0.1/', 'http://127.0.0.1:80/'], 
                        tasks=['http_baseline', 'port_scan'])
        
        self.assertEqual(result['status'], 'paused_backpressure')
        # Should only have http_baseline for first target
        self.assertEqual(len(result['results']), 1)
        self.assertGreater(result['unprocessed_count'], 0)
    
    def test_window_expiry_stops_execution(self):
        """Window expiry stops all remaining execution"""
        from yf_tools.assessment_run import run, check_window
        from yf_tools.assessment_plan import PlanError
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline', 'port_scan']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        policy['port_scan_ports'] = [80]
        
        # Mock check_window to pass first time (validation), fail second time (execution)
        call_count = [0]
        def mock_check_window(p):
            call_count[0] += 1
            if call_count[0] > 1:  # Fail after validation
                raise PlanError('window expired')
        
        with patch('yf_tools.assessment_run.check_window', side_effect=mock_check_window):
            result = run(policy, ['http://127.0.0.1/'], 
                        tasks=['http_baseline', 'port_scan'])
        
        self.assertEqual(result['status'], 'window_expired')
    
    def test_aggregate_status_calculation(self):
        """Aggregate status correctly reflects mixed results"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline', 'port_scan']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        policy['port_scan_ports'] = [80]
        
        with patch('yf_tools.http_baseline.inspect') as mock_http, \
             patch('yf_tools.nmap_baseline.scan') as mock_nmap:
            
            # One success, one error
            mock_http.return_value = {'kind': 'http_baseline', 'status': 'observed'}
            mock_nmap.return_value = {'kind': 'port_scan', 'status': 'nmap_error'}
            
            result = run(policy, ['http://127.0.0.1/'], 
                        tasks=['http_baseline', 'port_scan'])
        
        self.assertEqual(result['status'], 'completed_with_errors')
        self.assertIn('failed_count', result)
        self.assertEqual(result['failed_count'], 1)
    
    def test_per_type_counts_in_result(self):
        """Result includes per-type counts"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline', 'port_scan', 'template_scan']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        policy['port_scan_ports'] = [80]
        policy['nuclei_templates'] = ['test.yaml']
        policy['approved_template_dir'] = '/tmp/templates'
        
        with patch('yf_tools.http_baseline.inspect') as mock_http, \
             patch('yf_tools.nmap_baseline.scan') as mock_nmap, \
             patch('yf_tools.nuclei_scan.execute_scan') as mock_nuclei:
            
            mock_http.return_value = {'kind': 'http_baseline', 'status': 'observed'}
            mock_nmap.return_value = {'kind': 'port_scan', 'status': 'completed', 'ports': []}
            mock_nuclei.return_value = {'kind': 'nuclei_template_scan', 'status': 'completed', 'matches': []}
            
            result = run(policy, ['http://127.0.0.1/', 'http://127.0.0.1:80/'], 
                        tasks=['http_baseline', 'port_scan', 'template_scan'])
        
        self.assertIn('task_counts', result)
        self.assertEqual(result['task_counts']['http_baseline'], 2)
        self.assertEqual(result['task_counts']['port_scan'], 2)
        self.assertEqual(result['task_counts']['template_scan'], 2)
    
    def test_backward_compat_http_only_without_tasks_param(self):
        """Backward compatibility: run without tasks param defaults to http_baseline only"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        
        with patch('yf_tools.http_baseline.inspect') as mock_http:
            mock_http.return_value = {'kind': 'http_baseline', 'status': 'observed'}
            # Call without tasks parameter
            result = run(policy, ['http://127.0.0.1/'])
        
        self.assertEqual(result['kind'], 'http_assessment_run')
        self.assertEqual(len(result['results']), 1)
    
    def test_task_type_discriminator_in_each_result(self):
        """Each result has task_type discriminator"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline', 'port_scan']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        policy['port_scan_ports'] = [80]
        
        with patch('yf_tools.http_baseline.inspect') as mock_http, \
             patch('yf_tools.nmap_baseline.scan') as mock_nmap:
            
            mock_http.return_value = {'kind': 'http_baseline', 'status': 'observed'}
            mock_nmap.return_value = {'kind': 'port_scan', 'status': 'completed', 'ports': []}
            
            result = run(policy, ['http://127.0.0.1/'], 
                        tasks=['http_baseline', 'port_scan'])
        
        for res in result['results']:
            self.assertIn('task_type', res)
            self.assertIn(res['task_type'], ['http_baseline', 'port_scan', 'template_scan'])
    
    def test_fatal_error_stops_all_execution(self):
        """Fatal errors (not task-specific) stop all execution"""
        from yf_tools.assessment_run import run
        policy = self.base_policy()
        policy['allowed_tests'] = ['http_baseline']
        policy['http_ports'] = [80]
        policy['http_paths'] = ['/']
        
        with patch('yf_tools.http_baseline.inspect') as mock_http:
            # Simulate fatal error like KeyboardInterrupt
            mock_http.side_effect = KeyboardInterrupt()
            
            with self.assertRaises(KeyboardInterrupt):
                run(policy, ['http://127.0.0.1/'], tasks=['http_baseline'])


if __name__ == '__main__':
    unittest.main()
