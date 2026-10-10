"""Sequential, window-bound HTTP baseline runner. No other scan types executed."""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit
from yf_tools.assessment_plan import build_plan, PlanError
from yf_tools.http_baseline import inspect


def check_window(policy):
    try:
        start = datetime.fromisoformat(policy['window_start'])
        end = datetime.fromisoformat(policy['window_end'])
        now = datetime.now(timezone.utc)
        if start.tzinfo is None or end.tzinfo is None or not start <= now < end:
            raise ValueError('inactive window')
    except (KeyError, TypeError, ValueError) as exc:
        raise PlanError('active timezone-aware testing window required') from exc


def validate(policy, targets):
    if not isinstance(policy, dict):
        raise PlanError('policy must be an object')
    check_window(policy)
    limit = policy.get('max_targets')
    if type(limit) is not int or limit < 1 or not isinstance(targets, list) or not 0 < len(targets) <= limit:
        raise PlanError('target count outside max_targets')
    if policy.get('allowed_tests') != ['http_baseline']:
        raise PlanError('runner supports http_baseline only')
    paths = policy.get('http_paths')
    ports = policy.get('http_ports')
    if not isinstance(paths, list) or not paths or not all(isinstance(p,str) and p.startswith('/') for p in paths):
        raise PlanError('explicit http_paths required')
    if not isinstance(ports,list) or not ports or not all(type(p) is int and 1 <= p <= 65535 for p in ports):
        raise PlanError('explicit http_ports required')
    for target in targets:
        plan = build_plan(policy, target)
        url = urlsplit(target)
        try:
            address = ipaddress.ip_address(plan['host'])
        except ValueError as exc:
            raise PlanError('literal IP required') from exc
        if address.is_unspecified or address.is_multicast:
            raise PlanError('unsupported IP')
        if url.scheme not in ('http','https') or url.query or url.fragment:
            raise PlanError('invalid target URL')
        if (url.path or '/') not in paths or (url.port or (443 if url.scheme == 'https' else 80)) not in ports:
            raise PlanError('path or port not approved')


def run(policy, targets):
    validate(policy, targets)
    results = []
    next_start = None
    interval = 1 / policy['requests_per_second']
    for index, target in enumerate(targets):
        now = time.monotonic()
        if next_start is not None and now < next_start:
            time.sleep(next_start - now)
            now = next_start
        try:
            check_window(policy)
        except PlanError:
            return {'kind':'http_assessment_run','status':'window_expired', 'results':results,
                    'unprocessed_count':len(targets)-index}
        next_start = now + interval
        result = inspect(policy, target)
        results.append({'target_index':index, **result})
        if result.get('http_status') in (429,503):
            return {'kind':'http_assessment_run','status':'paused_backpressure', 'results':results,
                    'unprocessed_count':len(targets)-index-1}
    failed_count = sum(item.get('status') != 'observed' for item in results)
    return {'kind':'http_assessment_run',
            'status':'completed_with_errors' if failed_count else 'completed',
            'results':results, 'failed_count':failed_count,
            'unprocessed_count':0, 'vulnerability_verified':False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--targets', required=True, help='JSON array of approved URLs')
    args = parser.parse_args()
    try:
        result = run(json.loads(Path(args.policy).read_text()), json.loads(Path(args.targets).read_text()))
    except (OSError, ValueError):
        print('assessment_run: invalid input or inactive authorization', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('assessment_run: interrupted; no automatic retry', file=sys.stderr)
        return 130
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'completed' else 2

if __name__ == '__main__':
    sys.exit(main())
