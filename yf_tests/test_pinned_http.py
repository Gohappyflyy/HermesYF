"""Real loopback fixtures; DNS is mocked and never queried externally."""
import json
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from yf_tools.assessment_plan import PlanError
from yf_tools.http_baseline import inspect


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.server.seen.append((self.command, self.path, self.headers['Host']))
        self.send_response(302 if self.path == '/redirect' else 200)
        self.send_header('Location', 'http://outside.invalid/secret')
        self.send_header('Content-Security-Policy', 'SECRET')
        self.send_header('Set-Cookie', 'SECRET')
        self.end_headers()

    def log_message(self, *args):
        pass


def answers(port, addresses):
    return [(socket.AF_INET6 if ':' in ip else socket.AF_INET,
             socket.SOCK_STREAM, socket.IPPROTO_TCP, '',
             (ip, port, 0, 0) if ':' in ip else (ip, port)) for ip in addresses]


class PinnedHTTPTests(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.seen = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port
        now = datetime.now(timezone.utc)
        self.policy = {'targets': ['app.test'], 'allowed_tests': ['http_baseline'],
                       'requests_per_second': 10, 'http_ports': [self.port],
                       'dns_addresses': {'app.test': ['127.0.0.1']},
                       'allow_private_dns': True, 'http_paths': ['/', '/redirect'],
                       'max_targets': 2,
                       'window_start': (now - timedelta(minutes=1)).isoformat(),
                       'window_end': (now + timedelta(minutes=1)).isoformat()}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def url(self, path='/'):
        return f'http://app.test:{self.port}{path}'

    def test_real_head_host_no_proxy_no_redirect_no_secrets(self):
        with patch('socket.getaddrinfo', return_value=answers(self.port, ['127.0.0.1'])) as dns, \
             patch.dict('os.environ', {'http_proxy': 'http://127.0.0.1:1'}):
            result = inspect(self.policy, self.url('/redirect'))
        dns.assert_called_once_with('app.test', self.port, socket.AF_UNSPEC,
                                    socket.SOCK_STREAM, socket.IPPROTO_TCP)
        self.assertEqual(self.server.seen, [('HEAD', '/redirect', f'app.test:{self.port}')])
        self.assertEqual(result['http_status'], 302)
        self.assertFalse(result['redirect_followed'])
        self.assertTrue(result['header_presence']['content-security-policy'])
        self.assertNotIn('SECRET', json.dumps(result))
        self.assertNotIn('outside.invalid', json.dumps(result))

    def test_mixed_ipv4_ipv6_answers_rejected_before_connection(self):
        with patch('socket.getaddrinfo', return_value=answers(self.port, ['127.0.0.1', '2606:4700:4700::1111'])), \
             patch('socket.socket.connect') as connect:
            with self.assertRaises(PlanError):
                inspect(self.policy, self.url())
            connect.assert_not_called()
        self.assertEqual(self.server.seen, [])

    def test_private_dns_requires_exact_true(self):
        for flag in (None, False, 'true', 1):
            with self.subTest(flag=flag):
                self.policy['allow_private_dns'] = flag
                with patch('socket.getaddrinfo', return_value=answers(self.port, ['127.0.0.1'])), \
                     patch('socket.socket.connect') as connect:
                    with self.assertRaises(PlanError):
                        inspect(self.policy, self.url())
                    connect.assert_not_called()

    def test_missing_or_malformed_map_rejected_without_dns(self):
        for value in (None, {}, {'app.test': []}, {'app.test': '127.0.0.1'},
                      {'app.test': ['127.0.0.0/8']}, {'app.test': [1]}):
            with self.subTest(value=value), patch('socket.getaddrinfo') as dns:
                self.policy['dns_addresses'] = value
                with self.assertRaises(PlanError):
                    inspect(self.policy, self.url())
                dns.assert_not_called()

    def test_empty_or_failed_dns_fail_closed(self):
        for value in ([], socket.gaierror('fixture')):
            kwargs = {'side_effect': value} if isinstance(value, Exception) else {'return_value': value}
            with self.subTest(value=value), patch('socket.getaddrinfo', **kwargs), \
                 patch('socket.socket.connect') as connect:
                with self.assertRaises(PlanError):
                    inspect(self.policy, self.url())
                connect.assert_not_called()

    def test_exact_scope_not_subdomains_or_ip_scope(self):
        for target in (f'http://sub.app.test:{self.port}/', self.url()):
            p = dict(self.policy)
            if target == self.url():
                p['targets'] = ['127.0.0.0/8']
            with patch('socket.getaddrinfo') as dns:
                with self.assertRaises(PlanError):
                    inspect(p, target)
                dns.assert_not_called()

    def test_unapproved_port_before_dns(self):
        self.policy['http_ports'] = [1]
        with patch('socket.getaddrinfo') as dns:
            with self.assertRaises(PlanError):
                inspect(self.policy, self.url())
            dns.assert_not_called()

    def test_runner_domain_real_request(self):
        from yf_tools.assessment_run import run
        with patch('socket.getaddrinfo', return_value=answers(self.port, ['127.0.0.1'])) as dns:
            result = run(self.policy, [self.url()])
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(len(self.server.seen), 1)
        self.assertEqual(dns.call_count, 1)

    def test_runner_missing_map_prevalidates_entire_batch(self):
        from yf_tools.assessment_run import run
        self.policy['targets'].append('other.test')
        with patch('yf_tools.assessment_run.inspect') as send:
            with self.assertRaises(PlanError):
                run(self.policy, [self.url(), f'http://other.test:{self.port}/'])
            send.assert_not_called()

    def test_dns_rebinding_between_requests_is_revalidated(self):
        inspect_url = self.url()
        with patch('socket.getaddrinfo', side_effect=[answers(self.port, ['127.0.0.1']),
                                                    answers(self.port, ['127.0.0.2'])]):
            self.assertEqual(inspect(self.policy, inspect_url)['status'], 'observed')
            with self.assertRaises(PlanError):
                inspect(self.policy, inspect_url)
        self.assertEqual(len(self.server.seen), 1)

    def test_unspecified_multicast_always_rejected(self):
        for ip in ('0.0.0.0', '224.0.0.1', '::', 'ff02::1'):
            self.policy['dns_addresses']['app.test'] = [ip]
            with self.subTest(ip=ip), patch('socket.getaddrinfo', return_value=answers(self.port, [ip])), \
                 patch('socket.socket.connect') as connect:
                with self.assertRaises(PlanError):
                    inspect(self.policy, self.url())
                connect.assert_not_called()

    def test_private_linklocal_and_mapped_addresses_rejected_by_default(self):
        self.policy.pop('allow_private_dns')
        for ip in ('10.1.2.3', '169.254.1.2', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1'):
            self.policy['dns_addresses']['app.test'] = [ip]
            with self.subTest(ip=ip), patch('socket.getaddrinfo', return_value=answers(self.port, [ip])), \
                 patch('socket.socket.connect') as connect:
                with self.assertRaises(PlanError):
                    inspect(self.policy, self.url())
                connect.assert_not_called()

    def test_head_never_reads_response_body(self):
        with patch('socket.getaddrinfo', return_value=answers(self.port, ['127.0.0.1'])), \
             patch('http.client.HTTPResponse.read', side_effect=AssertionError('body read')) as read:
            self.assertEqual(inspect(self.policy, self.url())['http_status'], 200)
            read.assert_not_called()

    def test_public_ipv6_numeric_socket_no_second_resolution(self):
        from yf_tools.pinned_http import resolve, PinnedHTTPConnection
        p = {'dns_addresses': {'app.test': ['2606:4700:4700::1111']}}
        with patch('socket.getaddrinfo', return_value=answers(80, ['2606:4700:4700::1111'])) as dns:
            vetted = resolve(p, 'app.test', 80)
            with patch('socket.socket') as sock:
                conn = PinnedHTTPConnection('app.test', 80, vetted[0], timeout=10)
                conn.connect()
                sock.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                sock.return_value.connect.assert_called_once_with(('2606:4700:4700::1111', 80, 0, 0))
            self.assertEqual(dns.call_count, 1)

    def test_tls_trusted_ca_sni_and_hostname_verification(self):
        from yf_tools.pinned_http import head
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def openssl(*args):
                subprocess.run(['openssl', *args], cwd=root, check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            openssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key',
                    '-out', 'ca.pem', '-days', '1', '-subj', '/CN=Fixture CA')
            openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'server.key',
                    '-out', 'server.csr', '-subj', '/CN=app.test')
            (root / 'ext.cnf').write_text('subjectAltName=DNS:app.test\nextendedKeyUsage=serverAuth\n')
            openssl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key',
                    '-CAcreateserial', '-out', 'server.pem', '-days', '1', '-extfile', 'ext.cnf')
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / 'server.pem', root / 'server.key')
            sni = []
            context.set_servername_callback(lambda sock, name, ctx: sni.append(name))
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            trusted = ssl.create_default_context(cafile=str(root / 'ca.pem'))
            with patch('socket.getaddrinfo', return_value=answers(self.port, ['127.0.0.1'])):
                with head(self.policy, 'app.test', self.port, 'https', '/', ssl_context=trusted) as response:
                    self.assertEqual(response.status, 200)
                self.assertEqual(sni, ['app.test'])
                self.assertEqual(self.server.seen[0][2], f'app.test:{self.port}')
                p = dict(self.policy, dns_addresses={'wrong.test': ['127.0.0.1']})
                with self.assertRaises(ssl.SSLCertVerificationError):
                    with head(p, 'wrong.test', self.port, 'https', '/', ssl_context=trusted):
                        self.fail('wrong hostname accepted')
                with self.assertRaises(ssl.SSLCertVerificationError):
                    with head(self.policy, 'app.test', self.port, 'https', '/'):
                        self.fail('untrusted CA accepted')
            self.assertEqual(len(self.server.seen), 1)
