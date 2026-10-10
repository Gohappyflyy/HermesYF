"""Discover assessment CLIs; version probes only, never target scans or installs."""
import json
import shutil
import subprocess

TOOLS = {
    'curl': ['--version'],
    'openssl': ['version'],
    'dig': ['-v'],
    'nmap': ['--version'],
    'httpx': ['-version'],
    'nuclei': ['-version'],
    'ffuf': ['-V'],
    'testssl.sh': ['--version'],
}


def inspect_tool(name, version_args):
    path = shutil.which(name)
    result = {'tool': name, 'path': path, 'status': 'missing'}
    if path is None:
        return result
    try:
        probe = subprocess.run([path, *version_args], shell=False, timeout=5,
                               capture_output=True, text=True, errors='replace')
    except subprocess.TimeoutExpired:
        result['status'] = 'probe_timeout'
        return result
    except OSError:
        result['status'] = 'probe_failed'
        return result
    output = (probe.stdout + '\n' + probe.stderr).strip()
    result.update(status='available' if probe.returncode == 0 else 'probe_failed',
                  returncode=probe.returncode, version_output=output[:2000])
    # The Python HTTP client also ships a CLI named httpx; do not misidentify it.
    if name == 'httpx' and result['status'] == 'available':
        if 'projectdiscovery' not in output.lower():
            result['status'] = 'identity_unverified'
    return result


if __name__ == '__main__':
    print(json.dumps({'kind': 'local_tool_version_inventory',
                      'target_requests': False,
                      'tools': [inspect_tool(name, args) for name, args in TOOLS.items()]},
                     indent=2, sort_keys=True))
