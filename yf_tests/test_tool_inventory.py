import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import subprocess


class ToolInventoryTests(unittest.TestCase):
    def test_missing_tool_does_not_run(self):
        from yf_tools.tool_inventory import inspect_tool
        with patch('shutil.which', return_value=None), patch('subprocess.run') as run:
            result = inspect_tool('nmap', ['--version'])
        self.assertEqual(result['status'], 'missing')
        run.assert_not_called()

    def test_probe_uses_no_shell_and_timeout(self):
        from yf_tools.tool_inventory import inspect_tool
        with patch('shutil.which', return_value='/bin/nmap'), patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'Nmap 7', '')) as run:
            result = inspect_tool('nmap', ['--version'])
        self.assertEqual(result['status'], 'available')
        self.assertEqual(result['version_output'], 'Nmap 7')
        self.assertFalse(run.call_args.kwargs['shell'])
        self.assertEqual(run.call_args.kwargs['timeout'], 5)
        self.assertEqual(run.call_args.args[0], ['/bin/nmap', '--version'])

    def test_timeout_is_not_available(self):
        from yf_tools.tool_inventory import inspect_tool
        with patch('shutil.which', return_value='/bin/nmap'), patch('subprocess.run', side_effect=subprocess.TimeoutExpired('nmap', 5)):
            self.assertEqual(inspect_tool('nmap', ['--version'])['status'], 'probe_timeout')

    def test_failed_probe_is_not_available(self):
        from yf_tools.tool_inventory import inspect_tool
        with patch('shutil.which', return_value='/bin/nmap'), patch('subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'bad')):
            self.assertEqual(inspect_tool('nmap', ['--version'])['status'], 'probe_failed')

    def test_httpx_package_collision_not_accepted(self):
        from yf_tools.tool_inventory import inspect_tool
        with patch('shutil.which', return_value='/bin/httpx'), patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'Python HTTPX client', '')):
            self.assertEqual(inspect_tool('httpx', ['-version'])['status'], 'identity_unverified')

    def test_output_limit(self):
        from yf_tools.tool_inventory import inspect_tool
        with patch('shutil.which', return_value='/bin/nmap'), patch('subprocess.run', return_value=subprocess.CompletedProcess([], 0, 'x'*5000, '')):
            self.assertLessEqual(len(inspect_tool('nmap', ['--version'])['version_output']), 2000)
