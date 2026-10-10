"""Offline Nuclei JSONL candidate reporting; not a scanner or proof of vulnerability."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, urlunsplit

class ReportError(ValueError):
    pass


def summarize(rows):
    findings = {}
    total = 0
    for row in rows:
        total += 1
        if not isinstance(row, dict):
            raise ReportError('finding must be an object')
        template = row.get('template-id')
        target = row.get('matched-at')
        if not isinstance(template, str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,200}', template):
            raise ReportError('invalid template ID')
        if not isinstance(target, str):
            raise ReportError('missing matched-at URL')
        try:
            url = urlsplit(target)
            if url.scheme not in ('https', 'http') or not url.hostname or url.username is not None or url.password is not None:
                raise ReportError('unsupported or credential-bearing URL')
            _ = url.port
        except ValueError as exc:
            raise ReportError('invalid target URL') from exc
        # Query/fragment and raw evidence are intentionally not carried forward.
        target = urlunsplit((url.scheme.lower(), url.netloc.lower(), url.path, '', ''))
        info = row.get('info', {})
        if not isinstance(info, dict):
            raise ReportError('invalid info object')
        severity = info.get('severity')
        if severity not in ('info', 'low', 'medium', 'high', 'critical', 'unknown'):
            severity = 'unknown'
        key = (target, template, severity)
        if key not in findings:
            findings[key] = {'target': target, 'template_id': template, 'severity': severity,
                             'verification': 'unverified', 'occurrences': 0}
        findings[key]['occurrences'] += 1
    return {'kind': 'nuclei_candidate_summary', 'input_rows': total,
            'findings': [findings[key] for key in sorted(findings)],
            'limitations': ['Not vulnerability validation or coverage proof',
                            'Query removal can merge distinct endpoints',
                            'URL paths and template IDs may still contain sensitive data; review before sharing']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, help='local Nuclei JSONL file')
    args = parser.parse_args()
    try:
        data = Path(args.input).read_bytes()
        rows = [json.loads(line) for line in data.decode('utf-8').splitlines() if line.strip()]
        result = summarize(rows)
    except (OSError, ValueError, UnicodeError):
        print('scan_report: invalid or unreadable JSONL input', file=sys.stderr)
        return 1
    result['input_sha256'] = hashlib.sha256(data).hexdigest()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0

if __name__ == '__main__':
    sys.exit(main())
