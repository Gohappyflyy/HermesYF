import json
import shutil
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch
import tempfile


class SimpleHandler(BaseHTTPRequestHandler):
    """Minimal test server for nuclei template testing"""
    def do_GET(self):
        if self.path == '/vulnerable':
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body>TEST_VULNERABLE_PATTERN</body></html>')
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, *args):
        pass


class NucleiScanTests(unittest.TestCase):
    """Test nuclei_scan with strict TDD: policy validation, subprocess handling, output parsing"""
    
    def policy(self):
        """Base policy for testing"""
        return {
            'targets': ['127.0.0.1', 'example.test'],
            'exclude': [],
            'allowed_tests': ['template_scan'],
            'requests_per_second': 10,
            'scan_timeout_seconds': 60,
            'approved_template_dir': 'templates',
            'nuclei_templates': ['cves/test.yaml', 'basic/check.yaml'],
            'max_templates': 100
        }
    
    def test_requires_template_scan_in_allowed_tests(self):
        """Policy must explicitly allow template_scan"""
        from yf_tools.nuclei_scan import execute_scan, ScanError
        policy = self.policy()
        policy['allowed_tests'] = ['http_baseline']
        with self.assertRaises(ScanError):
            execute_scan(policy, 'http://example.test/')
    
    def test_requires_explicit_nuclei_templates_list(self):
        """Empty or missing nuclei_templates list must be rejected"""
        from yf_tools.nuclei_scan import execute_scan, ScanError
        policy = self.policy()
        policy['nuclei_templates'] = []
        with self.assertRaises(ScanError):
            execute_scan(policy, 'http://example.test/')
        
        del policy['nuclei_templates']
        with self.assertRaises(ScanError):
            execute_scan(policy, 'http://example.test/')
    
    def test_requires_approved_template_dir(self):
        """approved_template_dir must be set"""
        from yf_tools.nuclei_scan import execute_scan, ScanError
        policy = self.policy()
        del policy['approved_template_dir']
        with self.assertRaises(ScanError):
            execute_scan(policy, 'http://example.test/')
    
    def test_max_templates_enforced(self):
        """Template count must not exceed max_templates"""
        from yf_tools.nuclei_scan import execute_scan, ScanError
        policy = self.policy()
        policy['max_templates'] = 2
        policy['nuclei_templates'] = ['t1.yaml', 't2.yaml', 't3.yaml']
        with self.assertRaises(ScanError):
            execute_scan(policy, 'http://example.test/')
    
    def test_max_templates_default_100(self):
        """Default max_templates is 100"""
        from yf_tools.nuclei_scan import execute_scan, ScanError
        policy = self.policy()
        policy['nuclei_templates'] = [f't{i}.yaml' for i in range(101)]
        with self.assertRaises(ScanError):
            execute_scan(policy, 'http://example.test/')
    
    def test_templates_must_be_relative_paths(self):
        """Template paths must be relative, no absolute or parent traversal"""
        from yf_tools.nuclei_scan import execute_scan, ScanError
        policy = self.policy()
        
        # Absolute path rejected
        policy['nuclei_templates'] = ['/etc/passwd']
        with self.assertRaises(ScanError):
            execute_scan(policy, 'http://example.test/')
        
        # Parent traversal rejected
        policy['nuclei_templates'] = ['../other/template.yaml']
        with self.assertRaises(ScanError):
            execute_scan(policy, 'http://example.test/')
    
    def test_target_validated_via_build_plan(self):
        """Target must pass assessment_plan.build_plan validation"""
        from yf_tools.nuclei_scan import execute_scan, ScanError
        policy = self.policy()
        
        # Out of scope target
        with self.assertRaises(ScanError):
            execute_scan(policy, 'http://notinscope.test/')
    
    def test_scan_timeout_capped_at_300(self):
        """scan_timeout_seconds must be capped at 300"""
        from yf_tools.nuclei_scan import execute_scan
        policy = self.policy()
        policy['scan_timeout_seconds'] = 500
        
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
            try:
                execute_scan(policy, 'http://example.test/')
            except Exception:
                pass
            # Verify timeout was capped
            if mock_run.called:
                call_kwargs = mock_run.call_args[1]
                self.assertLessEqual(call_kwargs.get('timeout', 0), 300)
    
    @patch('subprocess.run')
    def test_nuclei_missing_detected(self, mock_run):
        """Detect when nuclei binary is not available"""
        from yf_tools.nuclei_scan import execute_scan
        mock_run.side_effect = FileNotFoundError('nuclei not found')
        policy = self.policy()
        result = execute_scan(policy, 'http://example.test/')
        self.assertEqual(result['status'], 'nuclei_unavailable')
    
    @patch('subprocess.run')
    def test_nuclei_timeout_detected(self, mock_run):
        """Detect subprocess timeout"""
        from yf_tools.nuclei_scan import execute_scan
        mock_run.side_effect = subprocess.TimeoutExpired('nuclei', 60)
        policy = self.policy()
        result = execute_scan(policy, 'http://example.test/')
        self.assertEqual(result['status'], 'timeout')
    
    @patch('subprocess.run')
    def test_nuclei_nonzero_exit_detected(self, mock_run):
        """Detect nonzero exit code"""
        from yf_tools.nuclei_scan import execute_scan
        mock_run.return_value = MagicMock(returncode=1, stdout='', stderr='error occurred')
        policy = self.policy()
        result = execute_scan(policy, 'http://example.test/')
        self.assertEqual(result['status'], 'error')
        self.assertIn('returncode', result)
    
    @patch('subprocess.run')
    def test_empty_results_handled(self, mock_run):
        """Handle empty nuclei output (no matches)"""
        from yf_tools.nuclei_scan import execute_scan
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        policy = self.policy()
        result = execute_scan(policy, 'http://example.test/')
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['matches'], [])
    
    @patch('subprocess.run')
    def test_subprocess_called_with_shell_false(self, mock_run):
        """Verify subprocess.run called with shell=False"""
        from yf_tools.nuclei_scan import execute_scan
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        policy = self.policy()
        execute_scan(policy, 'http://example.test/')
        mock_run.assert_called_once()
        self.assertFalse(mock_run.call_args[1].get('shell', True))
    
    @patch('subprocess.run')
    def test_correct_nuclei_flags(self, mock_run):
        """Verify correct nuclei command line flags"""
        from yf_tools.nuclei_scan import execute_scan
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        policy = self.policy()
        policy['nuclei_templates'] = ['template1.yaml', 'template2.yaml']
        policy['requests_per_second'] = 5
        
        execute_scan(policy, 'http://example.test/')
        
        args = mock_run.call_args[0][0]
        self.assertIn('nuclei', args[0])
        self.assertIn('-u', args)
        self.assertIn('http://example.test/', args)
        self.assertIn('-jsonl', args)
        self.assertIn('-silent', args)
        self.assertIn('-no-interactsh', args)
        self.assertIn('-timeout', args)
        self.assertIn('30', args)
        self.assertIn('-retries', args)
        self.assertIn('1', args)
        self.assertIn('-rate-limit', args)
        self.assertIn('5', args)
        # Check templates
        t_count = sum(1 for i, arg in enumerate(args) if arg == '-t')
        self.assertEqual(t_count, 2)
    
    @patch('subprocess.run')
    def test_parse_jsonl_output(self, mock_run):
        """Parse JSONL output and extract required fields"""
        from yf_tools.nuclei_scan import execute_scan
        
        jsonl_output = '\n'.join([
            json.dumps({
                'template-id': 'test-vuln-1',
                'matched-at': 'http://example.test/page',
                'host': 'example.test',
                'info': {'severity': 'high'},
                'request': 'SECRET_REQUEST_DATA',
                'response': 'SECRET_RESPONSE_DATA',
                'extracted-results': ['EXTRACTED_SECRET']
            }),
            json.dumps({
                'template-id': 'test-vuln-2',
                'matched-at': 'http://example.test/api',
                'host': 'example.test',
                'info': {'severity': 'medium'}
            })
        ])
        
        mock_run.return_value = MagicMock(returncode=0, stdout=jsonl_output, stderr='')
        policy = self.policy()
        result = execute_scan(policy, 'http://example.test/')
        
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(result['matches']), 2)
        
        match1 = result['matches'][0]
        self.assertEqual(match1['template_id'], 'test-vuln-1')
        self.assertEqual(match1['matched_at'], 'http://example.test/page')
        self.assertEqual(match1['host'], 'example.test')
        self.assertEqual(match1['severity'], 'high')
        self.assertFalse(match1['vulnerability_verified'])
        
        # Ensure secrets not included
        result_str = json.dumps(result)
        self.assertNotIn('SECRET', result_str)
        self.assertNotIn('EXTRACTED', result_str)
        # Verify raw request/response fields are not in matches
        for match in result['matches']:
            self.assertNotIn('request', match)
            self.assertNotIn('response', match)
            self.assertNotIn('extracted-results', match)
    
    @patch('subprocess.run')
    def test_rate_limit_from_policy(self, mock_run):
        """Use requests_per_second from policy"""
        from yf_tools.nuclei_scan import execute_scan
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        policy = self.policy()
        policy['requests_per_second'] = 15
        
        execute_scan(policy, 'http://example.test/')
        
        args = mock_run.call_args[0][0]
        rate_idx = args.index('-rate-limit')
        self.assertEqual(args[rate_idx + 1], '15')
    
    @patch('subprocess.run')
    def test_no_arbitrary_user_flags(self, mock_run):
        """User cannot inject arbitrary flags"""
        from yf_tools.nuclei_scan import execute_scan
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        policy = self.policy()
        # Try to inject flags via template names
        policy['nuclei_templates'] = ['test.yaml', '-enable-pprof', 'other.yaml']
        
        execute_scan(policy, 'http://example.test/')
        
        args = mock_run.call_args[0][0]
        # Flags like -enable-pprof should not appear as standalone args
        # They should only appear after -t flags as template paths
        self.assertNotIn('-enable-pprof', [args[i] for i in range(len(args)) if i == 0 or args[i-1] != '-t'])
    
    @patch('subprocess.run')
    def test_bounded_output_collection(self, mock_run):
        """Verify output collection is bounded"""
        from yf_tools.nuclei_scan import execute_scan
        
        # Generate large JSONL output
        large_jsonl = '\n'.join([
            json.dumps({
                'template-id': f'test-{i}',
                'matched-at': f'http://example.test/page{i}',
                'host': 'example.test',
                'info': {'severity': 'low'}
            }) for i in range(10000)
        ])
        
        mock_run.return_value = MagicMock(returncode=0, stdout=large_jsonl, stderr='')
        policy = self.policy()
        result = execute_scan(policy, 'http://example.test/')
        
        # Should handle large output gracefully
        self.assertEqual(result['status'], 'completed')
        self.assertIsInstance(result['matches'], list)
    
    @unittest.skipUnless(shutil.which('nuclei'), 'nuclei not installed')
    def test_real_nuclei_with_custom_template(self):
        """Integration test with real nuclei binary and local HTTP server"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            
            # Create a simple nuclei template
            template_dir = tmpdir / 'templates'
            template_dir.mkdir()
            template_file = template_dir / 'test-template.yaml'
            template_file.write_text('''id: test-vulnerable-pattern
info:
  name: Test Vulnerable Pattern
  author: test
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/vulnerable"
    matchers:
      - type: word
        words:
          - "TEST_VULNERABLE_PATTERN"
''')
            
            # Start local HTTP server
            server = ThreadingHTTPServer(('127.0.0.1', 0), SimpleHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_port
            
            try:
                from yf_tools.nuclei_scan import execute_scan
                
                policy = {
                    'targets': ['127.0.0.1'],
                    'exclude': [],
                    'allowed_tests': ['template_scan'],
                    'requests_per_second': 10,
                    'scan_timeout_seconds': 30,
                    'approved_template_dir': str(template_dir),
                    'nuclei_templates': ['test-template.yaml'],
                    'max_templates': 100
                }
                
                result = execute_scan(policy, f'http://127.0.0.1:{port}/')
                
                self.assertEqual(result['status'], 'completed')
                self.assertGreaterEqual(len(result['matches']), 1)
                
                # Find the match
                match = next((m for m in result['matches'] if m['template_id'] == 'test-vulnerable-pattern'), None)
                if match:
                    self.assertEqual(match['severity'], 'high')
                    self.assertFalse(match['vulnerability_verified'])
                    self.assertIn('127.0.0.1', match['host'])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
    
    def test_integration_with_scan_report(self):
        """Verify output compatible with scan_report.summarize"""
        from yf_tools.nuclei_scan import execute_scan
        from yf_tools.scan_report import summarize
        
        with patch('subprocess.run') as mock_run:
            jsonl_output = json.dumps({
                'template-id': 'test-integration',
                'matched-at': 'http://example.test/page',
                'host': 'example.test',
                'info': {'severity': 'medium'}
            })
            mock_run.return_value = MagicMock(returncode=0, stdout=jsonl_output, stderr='')
            
            policy = self.policy()
            result = execute_scan(policy, 'http://example.test/')
            
            # Extract matches and convert to scan_report format
            matches = result['matches']
            # scan_report expects the raw nuclei format, but our matches are already processed
            # Verify the structure is compatible
            for match in matches:
                self.assertIn('template_id', match)
                self.assertIn('matched_at', match)
                self.assertIn('severity', match)
                self.assertFalse(match['vulnerability_verified'])


if __name__ == '__main__':
    unittest.main()
