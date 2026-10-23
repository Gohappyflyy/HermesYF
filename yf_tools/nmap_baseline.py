"""TCP port scan with approved ports via nmap; no NSE/SYN/UDP/credentials."""
import argparse
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from yf_tools.assessment_plan import build_plan, PlanError


def scan(policy, target):
    """Execute nmap TCP port scan with policy-approved ports.
    
    Args:
        policy: Policy dict with targets, allowed_tests, port_scan_ports
        target: Target IP or hostname to scan
        
    Returns:
        Dict with kind='port_scan', status, ports list, vulnerability_verified=False
    """
    plan = build_plan(policy, target)
    
    # Verify port_scan is approved
    if 'port_scan' not in [t['type'] for t in plan['tasks']]:
        raise PlanError('port_scan not approved')
    
    # Validate port_scan_ports
    ports = policy.get('port_scan_ports')
    if not isinstance(ports, list):
        raise PlanError('port_scan_ports must be a list')
    if not ports:
        raise PlanError('port_scan_ports must be nonempty')
    if not all(isinstance(p, int) and 1 <= p <= 65535 for p in ports):
        raise PlanError('port_scan_ports must contain valid ports (1-65535)')
    if len(ports) > 64:
        raise PlanError('port_scan_ports limited to 64 ports maximum')
    
    # Check if nmap is available
    nmap_path = shutil.which('nmap')
    if nmap_path is None:
        return {
            'kind': 'port_scan',
            'status': 'nmap_unavailable',
            'vulnerability_verified': False
        }
    
    # Build nmap command - no user-controlled flags.
    port_list = ','.join(str(p) for p in ports)
    # --max-rate caps packets/sec inside the scan itself: the per-task scheduler only spaces
    # task starts, so without this a single nmap run floods at its own default speed and
    # requests_per_second stops meaning anything.
    try:
        _rps = float(policy.get('requests_per_second') or 1)
    except (TypeError, ValueError):
        _rps = 1.0
    max_rate = str(max(10, int(_rps * 20)))
    cmd = [
        nmap_path,
        '-sT',                    # TCP connect scan
        '-sV',                    # Version detection
        '--version-light',        # Light version detection
        '-Pn',                    # Skip host discovery
        '-n',                     # No DNS resolution
        '--max-retries', '1',     # Limit retries
        '--max-rate', max_rate,   # Bound packets/sec to the policy rate
        '--host-timeout', '120s', # Host timeout
        '-p', port_list,          # Port list
        '-oX', '-',               # XML output to stdout
        plan['host']              # Target from validated plan
    ]
    
    # Execute nmap with timeout
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False  # Security: no shell injection
        )
        stdout, stderr = proc.communicate(timeout=150)
        
        if proc.returncode != 0:
            return {
                'kind': 'port_scan',
                'status': 'nmap_error',
                'vulnerability_verified': False
            }
        
        # Parse XML output
        return parse_nmap_xml(stdout)
        
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        return {
            'kind': 'port_scan',
            'status': 'timeout',
            'vulnerability_verified': False
        }
    except Exception:
        return {
            'kind': 'port_scan',
            'status': 'parse_error',
            'vulnerability_verified': False
        }


def parse_nmap_xml(xml_bytes):
    """Parse nmap XML output into structured port results.
    
    Args:
        xml_bytes: Raw XML bytes from nmap -oX output
        
    Returns:
        Dict with kind, status, ports list
    """
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return {
            'kind': 'port_scan',
            'status': 'parse_error',
            'vulnerability_verified': False
        }
    
    ports = []
    
    # Find all port elements
    for host in root.findall('.//host'):
        for port_elem in host.findall('.//ports/port'):
            port_info = parse_port_element(port_elem)
            if port_info:
                ports.append(port_info)
    
    return {
        'kind': 'port_scan',
        'status': 'completed',
        'ports': ports,
        'vulnerability_verified': False
    }


def parse_port_element(port_elem):
    """Parse a single port XML element.
    
    Args:
        port_elem: ElementTree Element for a port
        
    Returns:
        Dict with port, protocol, state, service, product, version
        or None if parsing fails
    """
    try:
        port_num = int(port_elem.get('portid', '0'))
        protocol = port_elem.get('protocol', 'tcp')
        
        # Get state
        state_elem = port_elem.find('state')
        state = state_elem.get('state', 'unknown') if state_elem is not None else 'unknown'
        
        # Get service info - only structured fields, no banners/scripts
        service_elem = port_elem.find('service')
        service_name = ''
        product = ''
        version = ''
        
        if service_elem is not None:
            service_name = service_elem.get('name', '')
            product = service_elem.get('product', '')
            version = service_elem.get('version', '')
        
        return {
            'port': port_num,
            'protocol': protocol,
            'state': state,
            'service': service_name,
            'product': product,
            'version': version,
            'vulnerability_verified': False
        }
    except (ValueError, AttributeError):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True)
    parser.add_argument('--target', required=True)
    args = parser.parse_args()
    
    try:
        policy = json.loads(Path(args.policy).read_text())
        result = scan(policy, args.target)
    except (ValueError, OSError) as exc:
        print(f'nmap_baseline: invalid policy or target: {exc}', file=sys.stderr)
        return 1
    except PlanError as exc:
        print(f'nmap_baseline: {exc}', file=sys.stderr)
        return 1
    
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result['status'] == 'completed' else 2


if __name__ == '__main__':
    sys.exit(main())
