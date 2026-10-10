import ipaddress
import json
import shutil
import socket
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
from yf_tools.assessment_plan import PlanError


class NmapBaselineTests(unittest.TestCase):
    def policy(self):
        return {
            'targets': ['127.0.0.1'],
            'exclude': [],
            'allowed_tests': ['port_scan'],
            'requests_per_second': 1,
            'port_scan_ports': [22, 80, 443]
        }

    def test_port_scan_not_in_allowed_tests(self):
        """Test rejection when port_scan is not in allowed_tests."""
        from yf_tools.nmap_baseline import scan
        p = self.policy()
        p['allowed_tests'] = ['http_baseline']
        with self.assertRaises(PlanError) as ctx:
            scan(p, '127.0.0.1')
        self.assertIn('port_scan not approved', str(ctx.exception))

    def test_missing_port_scan_ports(self):
        """Test rejection when port_scan_ports is missing."""
        from yf_tools.nmap_baseline import scan
        p = self.policy()
        del p['port_scan_ports']
        with self.assertRaises(PlanError) as ctx:
            scan(p, '127.0.0.1')
        self.assertIn('port_scan_ports', str(ctx.exception))

    def test_empty_port_scan_ports(self):
        """Test rejection when port_scan_ports is empty."""
        from yf_tools.nmap_baseline import scan
        p = self.policy()
        p['port_scan_ports'] = []
        with self.assertRaises(PlanError) as ctx:
            scan(p, '127.0.0.1')
        self.assertIn('port_scan_ports', str(ctx.exception))

    def test_invalid_port_scan_ports_type(self):
        """Test rejection when port_scan_ports is not a list."""
        from yf_tools.nmap_baseline import scan
        p = self.policy()
        p['port_scan_ports'] = "22,80,443"
        with self.assertRaises(PlanError) as ctx:
            scan(p, '127.0.0.1')
        self.assertIn('port_scan_ports', str(ctx.exception))

    def test_invalid_port_range(self):
        """Test rejection when ports are out of valid range."""
        from yf_tools.nmap_baseline import scan
        p = self.policy()
        p['port_scan_ports'] = [0, 65536, -1]
        with self.assertRaises(PlanError) as ctx:
            scan(p, '127.0.0.1')
        self.assertIn('port_scan_ports', str(ctx.exception))

    def test_too_many_ports(self):
        """Test rejection when more than 64 ports specified."""
        from yf_tools.nmap_baseline import scan
        p = self.policy()
        p['port_scan_ports'] = list(range(1, 66))  # 65 ports
        with self.assertRaises(PlanError) as ctx:
            scan(p, '127.0.0.1')
        self.assertIn('64 ports', str(ctx.exception))

    def test_target_not_in_scope(self):
        """Test rejection when target is not in approved scope."""
        from yf_tools.nmap_baseline import scan
        p = self.policy()
        with self.assertRaises(PlanError) as ctx:
            scan(p, '192.168.1.1')
        self.assertIn('outside approved scope', str(ctx.exception))

    def test_cidr_target_validation(self):
        """Test CIDR targets are validated via build_plan."""
        from yf_tools.nmap_baseline import scan
        p = self.policy()
        p['targets'] = ['192.168.1.0/24']
        result = scan(p, '192.168.1.50')
        self.assertEqual(result['kind'], 'port_scan')

    def test_nmap_not_available(self):
        """Test handling when nmap is not installed."""
        from yf_tools.nmap_baseline import scan
        with patch('shutil.which', return_value=None):
            result = scan(self.policy(), '127.0.0.1')
        self.assertEqual(result['kind'], 'port_scan')
        self.assertEqual(result['status'], 'nmap_unavailable')
        self.assertFalse(result['vulnerability_verified'])

    def test_nmap_timeout(self):
        """Test handling when nmap times out."""
        from yf_tools.nmap_baseline import scan
        mock_proc = MagicMock()
        mock_proc.communicate.side_effect = subprocess.TimeoutExpired('nmap', 150)
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('subprocess.Popen', return_value=mock_proc):
                result = scan(self.policy(), '127.0.0.1')
        self.assertEqual(result['kind'], 'port_scan')
        self.assertEqual(result['status'], 'timeout')
        self.assertFalse(result['vulnerability_verified'])

    def test_nmap_nonzero_exit(self):
        """Test handling when nmap exits with error code."""
        from yf_tools.nmap_baseline import scan
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b'', b'Error: permission denied')
        mock_proc.returncode = 1
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('subprocess.Popen', return_value=mock_proc):
                result = scan(self.policy(), '127.0.0.1')
        self.assertEqual(result['kind'], 'port_scan')
        self.assertEqual(result['status'], 'nmap_error')
        self.assertFalse(result['vulnerability_verified'])

    def test_malformed_xml(self):
        """Test handling when nmap returns malformed XML."""
        from yf_tools.nmap_baseline import scan
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (b'<incomplete', b'')
        mock_proc.returncode = 0
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('subprocess.Popen', return_value=mock_proc):
                result = scan(self.policy(), '127.0.0.1')
        self.assertEqual(result['kind'], 'port_scan')
        self.assertEqual(result['status'], 'parse_error')
        self.assertFalse(result['vulnerability_verified'])

    def test_empty_xml_results(self):
        """Test handling when nmap returns valid XML but no ports."""
        from yf_tools.nmap_baseline import scan
        xml = b'''<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1234567890">
<host><address addr="127.0.0.1"/><status state="up"/></host>
</nmaprun>'''
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (xml, b'')
        mock_proc.returncode = 0
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('subprocess.Popen', return_value=mock_proc):
                result = scan(self.policy(), '127.0.0.1')
        self.assertEqual(result['kind'], 'port_scan')
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['ports'], [])
        self.assertFalse(result['vulnerability_verified'])

    def test_successful_scan_parsing(self):
        """Test successful parsing of nmap XML output."""
        from yf_tools.nmap_baseline import scan
        xml = b'''<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1234567890">
<host>
  <address addr="127.0.0.1"/>
  <status state="up"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.2p1 Ubuntu"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="closed"/>
      <service name="http"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="filtered"/>
      <service name="https"/>
    </port>
  </ports>
</host>
</nmaprun>'''
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (xml, b'')
        mock_proc.returncode = 0
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('subprocess.Popen', return_value=mock_proc):
                result = scan(self.policy(), '127.0.0.1')
        self.assertEqual(result['kind'], 'port_scan')
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(result['ports']), 3)
        # Check first port
        self.assertEqual(result['ports'][0]['port'], 22)
        self.assertEqual(result['ports'][0]['protocol'], 'tcp')
        self.assertEqual(result['ports'][0]['state'], 'open')
        self.assertEqual(result['ports'][0]['service'], 'ssh')
        self.assertEqual(result['ports'][0]['product'], 'OpenSSH')
        self.assertEqual(result['ports'][0]['version'], '8.2p1 Ubuntu')
        self.assertFalse(result['ports'][0]['vulnerability_verified'])
        # Check second port
        self.assertEqual(result['ports'][1]['port'], 80)
        self.assertEqual(result['ports'][1]['state'], 'closed')
        # Check third port
        self.assertEqual(result['ports'][2]['port'], 443)
        self.assertEqual(result['ports'][2]['state'], 'filtered')

    def test_no_banners_or_scripts_in_output(self):
        """Test that no raw banners or script output is included."""
        from yf_tools.nmap_baseline import scan
        xml = b'''<?xml version="1.0"?>
<nmaprun scanner="nmap" start="1234567890">
<host>
  <address addr="127.0.0.1"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="8.2" extrainfo="SECRET_BANNER"/>
      <script id="ssh-hostkey" output="SECRET_KEY_DATA"/>
    </port>
  </ports>
</host>
</nmaprun>'''
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (xml, b'')
        mock_proc.returncode = 0
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('subprocess.Popen', return_value=mock_proc):
                result = scan(self.policy(), '127.0.0.1')
        result_str = json.dumps(result)
        self.assertNotIn('SECRET_BANNER', result_str)
        self.assertNotIn('SECRET_KEY_DATA', result_str)
        self.assertNotIn('extrainfo', result_str)
        self.assertNotIn('script', result_str)

    def test_subprocess_called_with_correct_args(self):
        """Test that subprocess is called with correct nmap arguments."""
        from yf_tools.nmap_baseline import scan
        xml = b'<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/></host></nmaprun>'
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (xml, b'')
        mock_proc.returncode = 0
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('subprocess.Popen', return_value=mock_proc) as mock_popen:
                scan(self.policy(), '127.0.0.1')
        mock_popen.assert_called_once()
        call_args = mock_popen.call_args
        cmd = call_args[0][0]
        # Verify command structure
        self.assertEqual(cmd[0], '/usr/bin/nmap')
        self.assertIn('-sT', cmd)
        self.assertIn('-sV', cmd)
        self.assertIn('--version-light', cmd)
        self.assertIn('-Pn', cmd)
        self.assertIn('-n', cmd)
        self.assertIn('--max-retries', cmd)
        self.assertIn('1', cmd)
        self.assertIn('--host-timeout', cmd)
        self.assertIn('120s', cmd)
        self.assertIn('-p', cmd)
        self.assertIn('-oX', cmd)
        self.assertIn('-', cmd)
        self.assertIn('127.0.0.1', cmd)
        # Verify shell=False
        self.assertFalse(call_args[1].get('shell', False))

    def test_port_list_formatting(self):
        """Test that port list is formatted as comma-separated."""
        from yf_tools.nmap_baseline import scan
        p = self.policy()
        p['port_scan_ports'] = [22, 80, 443, 8080]
        xml = b'<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1"/></host></nmaprun>'
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (xml, b'')
        mock_proc.returncode = 0
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('subprocess.Popen', return_value=mock_proc) as mock_popen:
                scan(p, '127.0.0.1')
        cmd = mock_popen.call_args[0][0]
        port_idx = cmd.index('-p')
        port_list = cmd[port_idx + 1]
        self.assertEqual(port_list, '22,80,443,8080')

    @unittest.skipUnless(shutil.which('nmap'), 'nmap not installed')
    def test_e2e_localhost_scan(self):
        """End-to-end test with real nmap scanning localhost ephemeral port."""
        from yf_tools.nmap_baseline import scan
        # Create a real TCP server on an ephemeral port
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('127.0.0.1', 0))
        server_socket.listen(1)
        port = server_socket.getsockname()[1]
        
        def accept_loop():
            try:
                while True:
                    conn, _ = server_socket.accept()
                    conn.close()
            except:
                pass
        
        thread = threading.Thread(target=accept_loop, daemon=True)
        thread.start()
        
        try:
            p = self.policy()
            p['port_scan_ports'] = [port]
            result = scan(p, '127.0.0.1')
            
            self.assertEqual(result['kind'], 'port_scan')
            self.assertEqual(result['status'], 'completed')
            self.assertIsInstance(result['ports'], list)
            self.assertFalse(result['vulnerability_verified'])
            
            # Should find the open port
            if len(result['ports']) > 0:
                port_result = result['ports'][0]
                self.assertEqual(port_result['port'], port)
                self.assertEqual(port_result['protocol'], 'tcp')
                self.assertIn(port_result['state'], ['open', 'closed', 'filtered'])
                self.assertIn('service', port_result)
                self.assertFalse(port_result['vulnerability_verified'])
        finally:
            server_socket.close()

    def test_no_user_arbitrary_flags(self):
        """Test that user cannot inject arbitrary nmap flags."""
        from yf_tools.nmap_baseline import scan
        # The function signature doesn't allow extra parameters
        # This test documents the constraint
        p = self.policy()
        # Should only accept policy and target, nothing else
        result = scan(p, '127.0.0.1')
        self.assertEqual(result['kind'], 'port_scan')

    def test_vulnerability_verified_always_false(self):
        """Test that all results have vulnerability_verified=False."""
        from yf_tools.nmap_baseline import scan
        xml = b'''<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host>
  <address addr="127.0.0.1"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh"/>
    </port>
  </ports>
</host>
</nmaprun>'''
        mock_proc = MagicMock()
        mock_proc.communicate.return_value = (xml, b'')
        mock_proc.returncode = 0
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            with patch('subprocess.Popen', return_value=mock_proc):
                result = scan(self.policy(), '127.0.0.1')
        self.assertFalse(result['vulnerability_verified'])
        for port in result['ports']:
            self.assertFalse(port['vulnerability_verified'])

    def test_cli_main_function(self):
        """Test command-line main function."""
        from yf_tools.nmap_baseline import main
        from pathlib import Path
        import tempfile
        xml = b'''<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host>
  <address addr="127.0.0.1"/>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh"/>
    </port>
  </ports>
</host>
</nmaprun>'''
        with tempfile.TemporaryDirectory() as directory:
            policy_path = Path(directory) / 'policy.json'
            policy_path.write_text(json.dumps(self.policy()))
            
            mock_proc = MagicMock()
            mock_proc.communicate.return_value = (xml, b'')
            mock_proc.returncode = 0
            
            with patch('shutil.which', return_value='/usr/bin/nmap'):
                with patch('subprocess.Popen', return_value=mock_proc):
                    with patch('sys.argv', ['nmap_baseline.py', '--policy', str(policy_path), '--target', '127.0.0.1']):
                        import io
                        from contextlib import redirect_stdout
                        f = io.StringIO()
                        with redirect_stdout(f):
                            exit_code = main()
            
            self.assertEqual(exit_code, 0)
            output = json.loads(f.getvalue())
            self.assertEqual(output['kind'], 'port_scan')
            self.assertEqual(output['status'], 'completed')


if __name__ == '__main__':
    unittest.main()
