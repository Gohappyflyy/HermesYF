"""Offline assessment planning. This module does not perform network requests."""
import argparse
import ipaddress
import json
import math
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

TESTS = {'http_baseline': 'HTTP status and headers',
         'tls_baseline': 'TLS certificate and configuration',
         'port_scan': 'Approved port scan',
         'crawl': 'Approved site crawl',
         'template_scan': 'Approved reviewed-template scan',
         'fuzz': 'Approved bounded fuzz test',
         'vulnerability_validation': 'Approved vulnerability validation'}

class PlanError(ValueError):
    pass


class ScopeViolation(PlanError):
    """The target resolved or was declared outside the approved scope.

    Distinct from a malformed plan: a scope violation means the policy and the live
    network disagree, so every remaining task in the run is untrustworthy — the runner
    aborts the chain instead of recording it as a per-task failure.
    """


def target_host(target):
    if not isinstance(target, str) or not target or target != target.strip():
        raise PlanError('invalid target')
    if '://' in target:
        try:
            url = urlsplit(target)
            if url.scheme not in ('http', 'https') or url.username is not None or url.password is not None:
                raise PlanError('unsupported URL or embedded credentials')
            _ = url.port
            host = url.hostname
        except ValueError as exc:
            raise PlanError('invalid target URL') from exc
    else:
        host = target
    if not host:
        raise PlanError('missing host')
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        host = host.rstrip('.').lower()
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
            raise PlanError('invalid hostname')
        return host


def matches(host, entry):
    if not isinstance(entry, str):
        raise PlanError('scope entries must be strings')
    if '/' in entry:
        try:
            network = ipaddress.ip_network(entry, strict=True)
        except ValueError as exc:
            raise PlanError('invalid scope CIDR') from exc
        try:
            return ipaddress.ip_address(host) in network
        except ValueError:
            return False
    return host == target_host(entry)


def build_plan(policy, target):
    if not isinstance(policy, dict):
        raise PlanError('policy must be an object')
    host = target_host(target)
    scopes = policy.get('targets', [])
    excluded = policy.get('exclude', [])
    tests = policy.get('allowed_tests', [])
    if not all(isinstance(v, list) for v in (scopes, excluded, tests)) or not scopes or not tests:
        raise PlanError('targets and allowed_tests must be nonempty lists')
    # Evaluate every entry, so invalid scope records are not hidden by short-circuiting.
    allowed_matches = [matches(host, entry) for entry in scopes]
    excluded_matches = [matches(host, entry) for entry in excluded]
    if any(excluded_matches) or not any(allowed_matches):
        raise PlanError('target outside approved scope')
    if not all(isinstance(test, str) and test in TESTS for test in tests):
        raise PlanError('unknown test type')
    rate = policy.get('requests_per_second')
    if isinstance(rate, bool) or not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate <= 0:
        raise PlanError('requests_per_second must be finite and positive')
    return {'kind': 'offline_assessment_plan', 'executed': False, 'host': host,
            'requests_per_second': rate,
            'tasks': [{'type': test, 'description': TESTS[test], 'status': 'planned'} for test in dict.fromkeys(tests)],
            'execution_requirements': ['Revalidate every destination and redirect',
                                       'Revalidate DNS addresses at execution time',
                                       'Use per-test approved parameters and time window']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--target', required=True)
    args = parser.parse_args()
    try:
        result = build_plan(json.loads(Path(args.policy).read_text()), args.target)
    except (OSError, ValueError) as exc:
        print('assessment_plan: invalid policy or target: ' + (str(exc) if isinstance(exc, PlanError) else type(exc).__name__), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0

if __name__ == '__main__':
    sys.exit(main())
