"""Nuclei template scanner executor with strict policy validation and bounded output.

严格的 Nuclei 模板扫描器执行器
==============================

本模块实现授权范围内的 Nuclei 模板扫描，遵循严格的 TDD 开发流程。

核心约束：
1. 策略验证：必须在 allowed_tests 中显式包含 'template_scan'
2. 模板白名单：必须提供显式的 nuclei_templates 列表（非空）
3. 模板目录：必须指定 approved_template_dir，所有模板路径相对此目录
4. 数量限制：模板数量不得超过 max_templates（默认100）
5. 路径安全：模板路径必须是相对路径，不允许绝对路径或父目录遍历（..）
6. 目标验证：通过 assessment_plan.build_plan 验证目标在授权范围内
7. 超时上限：scan_timeout_seconds 强制上限 300 秒

命令行参数（固定，用户不可注入）：
- nuclei -u <target> -t <template1> -t <template2> ...
- -jsonl -silent -no-interactsh
- -timeout 30 -retries 1
- -rate-limit <policy.requests_per_second>
- subprocess.run(shell=False, timeout=capped)

输出字段（每个匹配）：
- template_id: 模板ID
- matched_at: 匹配的URL
- host: 主机名
- severity: 严重程度
- vulnerability_verified: 固定为 False（所有结果都是候选，未经验证）

安全措施：
- 不输出原始 request/response/extracted-results
- 不支持用户任意标志
- 不允许 interactsh 或网络策略覆盖
- shell=False 防止命令注入
- 有界输出收集

状态码：
- completed: 扫描完成
- nuclei_unavailable: nuclei 二进制文件不可用
- timeout: 执行超时
- error: 非零退出码

局限性：
- 模板匹配只是候选，不是已验证的漏洞
- 不包含原始请求/响应数据
- 需要人工分析验证
- 不执行互联网扫描（测试中使用本地服务器）
"""
import json
import subprocess
from pathlib import Path
from yf_tools.assessment_plan import build_plan, PlanError


class ScanError(ValueError):
    """Raised when scan policy validation fails or scan cannot execute."""
    pass


def validate_policy(policy, target):
    """Validate policy requirements for nuclei template scanning.
    
    Args:
        policy: Policy dict with required keys
        target: Target URL to scan
        
    Raises:
        ScanError: If policy validation fails
    """
    if not isinstance(policy, dict):
        raise ScanError('policy must be an object')
    
    # Validate via build_plan (checks scope, allowed_tests, rate limits)
    try:
        plan = build_plan(policy, target)
    except PlanError as exc:
        raise ScanError(f'target validation failed: {exc}') from exc
    
    # Require template_scan in allowed_tests
    allowed_tests = policy.get('allowed_tests', [])
    if 'template_scan' not in allowed_tests:
        raise ScanError('template_scan not in allowed_tests')
    
    # Require explicit nuclei_templates list
    nuclei_templates = policy.get('nuclei_templates')
    if not isinstance(nuclei_templates, list) or not nuclei_templates:
        raise ScanError('explicit non-empty nuclei_templates list required')
    
    # Require approved_template_dir
    approved_dir = policy.get('approved_template_dir')
    if not isinstance(approved_dir, str) or not approved_dir:
        raise ScanError('approved_template_dir required')
    
    # Enforce max_templates (default 100)
    max_templates = policy.get('max_templates', 100)
    if not isinstance(max_templates, int) or max_templates <= 0:
        raise ScanError('max_templates must be positive integer')
    
    if len(nuclei_templates) > max_templates:
        raise ScanError(f'template count {len(nuclei_templates)} exceeds max_templates {max_templates}')
    
    # Validate template paths are relative and safe
    for template in nuclei_templates:
        if not isinstance(template, str):
            raise ScanError('template paths must be strings')
        
        template_path = Path(template)
        
        # Reject absolute paths
        if template_path.is_absolute():
            raise ScanError(f'absolute template path not allowed: {template}')
        
        # Reject parent directory traversal
        if '..' in template_path.parts:
            raise ScanError(f'parent directory traversal not allowed: {template}')
    
    return plan


def execute_scan(policy, target):
    """Execute nuclei template scan with strict policy enforcement.
    
    Args:
        policy: Policy dict with scan parameters
        target: Target URL to scan
        
    Returns:
        Dict with scan results containing:
        - status: 'completed', 'nuclei_unavailable', 'timeout', 'error'
        - matches: List of findings (if completed)
        - Each match: template_id, matched_at, host, severity, vulnerability_verified=False
        
    Raises:
        ScanError: If policy validation fails
    """
    # Validate policy and target
    plan = validate_policy(policy, target)
    
    # Build nuclei command
    approved_dir = policy['approved_template_dir']
    nuclei_templates = policy['nuclei_templates']
    requests_per_second = policy['requests_per_second']
    scan_timeout = min(policy.get('scan_timeout_seconds', 60), 300)  # Cap at 300
    
    # Build template arguments with full paths
    template_args = []
    for template in nuclei_templates:
        template_path = Path(approved_dir) / template
        template_args.extend(['-t', str(template_path)])
    
    # Construct nuclei command with required flags
    cmd = [
        'nuclei',
        '-u', target,
        *template_args,
        '-jsonl',
        '-silent',
        '-no-interactsh',
        '-timeout', '30',
        '-retries', '1',
        '-rate-limit', str(int(requests_per_second))
    ]
    
    # Execute nuclei subprocess
    try:
        result = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=scan_timeout
        )
    except FileNotFoundError:
        return {
            'kind': 'nuclei_template_scan',
            'status': 'nuclei_unavailable',
            'target': target,
            'matches': []
        }
    except subprocess.TimeoutExpired:
        return {
            'kind': 'nuclei_template_scan',
            'status': 'timeout',
            'target': target,
            'timeout_seconds': scan_timeout,
            'matches': []
        }
    
    # Check for errors
    if result.returncode != 0:
        return {
            'kind': 'nuclei_template_scan',
            'status': 'error',
            'target': target,
            'returncode': result.returncode,
            'stderr': result.stderr[:1000] if result.stderr else '',
            'matches': []
        }
    
    # Parse JSONL output
    matches = []
    if result.stdout:
        for line in result.stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                entry = json.loads(line)
                
                # Extract only allowed fields (no raw request/response/extracted data)
                match = {
                    'template_id': entry.get('template-id', 'unknown'),
                    'matched_at': entry.get('matched-at', ''),
                    'host': entry.get('host', ''),
                    'severity': entry.get('info', {}).get('severity', 'unknown'),
                    'vulnerability_verified': False
                }
                
                matches.append(match)
            except (json.JSONDecodeError, AttributeError, TypeError):
                # Skip malformed lines
                continue
    
    return {
        'kind': 'nuclei_template_scan',
        'status': 'completed',
        'target': target,
        'template_count': len(nuclei_templates),
        'match_count': len(matches),
        'matches': matches,
        'limitations': [
            'Template matches are candidates, not verified vulnerabilities',
            'No raw request/response data included',
            'Verification requires manual analysis'
        ]
    }


def main():
    """CLI entry point for nuclei template scanning."""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True, help='Policy JSON file')
    parser.add_argument('--target', required=True, help='Target URL to scan')
    parser.add_argument('--output', help='Output JSON file (optional)')
    args = parser.parse_args()
    
    try:
        policy = json.loads(Path(args.policy).read_text())
        result = execute_scan(policy, args.target)
    except (OSError, ValueError, ScanError) as exc:
        print(f'nuclei_scan: {exc}', file=sys.stderr)
        return 1
    
    output_json = json.dumps(result, indent=2, sort_keys=True)
    
    if args.output:
        try:
            output_path = Path(args.output)
            if output_path.exists():
                print('nuclei_scan: output file already exists', file=sys.stderr)
                return 2
            output_path.write_text(output_json)
        except OSError as exc:
            print(f'nuclei_scan: failed to write output: {exc}', file=sys.stderr)
            return 2
    else:
        print(output_json)
    
    return 0 if result['status'] == 'completed' else 3


if __name__ == '__main__':
    import sys
    sys.exit(main())
