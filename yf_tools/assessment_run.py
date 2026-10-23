"""Unified assessment runner: HTTP/Nmap/Nuclei with sequential execution and shared rate limiting.

统一评估运行器
==============

支持在一次批处理中执行多种任务类型（HTTP基线、端口扫描、模板扫描）。

核心特性：
1. 多任务类型：tasks=['http_baseline', 'port_scan', 'template_scan']
2. 策略验证：为启用的任务类型验证所有必需字段
   - http_baseline: http_ports + http_paths
   - port_scan: port_scan_ports
   - template_scan: nuclei_templates + approved_template_dir
3. 顺序执行：按目标 × 任务类型的笛卡尔积顺序执行
4. 共享速率限制：所有任务共享 window/rate_limit/max_targets
5. 结果收集：带 task_type 鉴别器的结果列表
6. 聚合状态：completed/completed_with_errors/paused_backpressure/window_expired
7. 任务隔离：单个任务错误不阻止其他任务（除非致命错误）
8. 每类计数：task_counts 统计每种任务类型的执行次数

向后兼容：不传 tasks 参数时默认为 http_baseline 仅模式（旧行为）。
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit
from yf_tools.assessment_plan import build_plan, PlanError, ScopeViolation
from yf_tools.http_baseline import inspect
from yf_tools.pinned_http import approved_addresses


# Supported task types
TASK_TYPES = {'http_baseline', 'port_scan', 'template_scan'}


def check_window(policy):
    try:
        start = datetime.fromisoformat(policy['window_start'])
        end = datetime.fromisoformat(policy['window_end'])
        now = datetime.now(timezone.utc)
        if start.tzinfo is None or end.tzinfo is None or not start <= now < end:
            raise ValueError('inactive window')
    except (KeyError, TypeError, ValueError) as exc:
        raise PlanError('active timezone-aware testing window required') from exc


def validate_http_baseline_policy(policy):
    """Validate policy requirements for HTTP baseline tasks."""
    paths = policy.get('http_paths')
    ports = policy.get('http_ports')
    if not isinstance(paths, list) or not paths or not all(isinstance(p, str) and p.startswith('/') for p in paths):
        raise PlanError('explicit http_paths required for http_baseline')
    if not isinstance(ports, list) or not ports or not all(type(p) is int and 1 <= p <= 65535 for p in ports):
        raise PlanError('explicit http_ports required for http_baseline')


def validate_port_scan_policy(policy):
    """Validate policy requirements for port scan tasks."""
    ports = policy.get('port_scan_ports')
    if not isinstance(ports, list) or not ports:
        raise PlanError('explicit non-empty port_scan_ports required for port_scan')
    if not all(isinstance(p, int) and 1 <= p <= 65535 for p in ports):
        raise PlanError('port_scan_ports must contain valid ports (1-65535)')


def validate_template_scan_policy(policy):
    """Validate policy requirements for template scan tasks."""
    nuclei_templates = policy.get('nuclei_templates')
    if not isinstance(nuclei_templates, list) or not nuclei_templates:
        raise PlanError('explicit non-empty nuclei_templates list required for template_scan')
    
    approved_dir = policy.get('approved_template_dir')
    if not isinstance(approved_dir, str) or not approved_dir:
        raise PlanError('approved_template_dir required for template_scan')


def validate_http_target(policy, target):
    """Validate HTTP target against policy constraints."""
    plan = build_plan(policy, target)
    url = urlsplit(target)
    try:
        address = ipaddress.ip_address(plan['host'])
    except ValueError:
        approved_addresses(policy, plan['host'])
        address = None
    if address is not None and (address.is_unspecified or address.is_multicast):
        raise PlanError('unsupported IP')
    if url.scheme not in ('http', 'https') or url.query or url.fragment:
        raise PlanError('invalid target URL')
    
    # Validate against http_paths and http_ports
    paths = policy.get('http_paths', [])
    ports = policy.get('http_ports', [])
    if paths and ((url.path or '/') not in paths):
        raise PlanError('path not approved')
    if ports and ((url.port or (443 if url.scheme == 'https' else 80)) not in ports):
        raise PlanError('port not approved')


def validate(policy, targets, tasks=None):
    """Validate policy and targets for specified tasks.
    
    Args:
        policy: Policy dict with required fields
        targets: List of target URLs/IPs
        tasks: List of task types to execute (default: ['http_baseline'] for backward compat)
    """
    if not isinstance(policy, dict):
        raise PlanError('policy must be an object')
    
    check_window(policy)
    
    limit = policy.get('max_targets')
    if type(limit) is not int or limit < 1 or not isinstance(targets, list) or not 0 < len(targets) <= limit:
        raise PlanError('target count outside max_targets')
    
    # Default to http_baseline only for backward compatibility
    if tasks is None:
        tasks = ['http_baseline']
    
    if not isinstance(tasks, list) or not tasks:
        raise PlanError('tasks must be a non-empty list')
    
    # Validate task types
    for task in tasks:
        if task not in TASK_TYPES:
            raise ValueError(f'unknown task type: {task}')
    
    # Validate policy has required fields for each task type
    if 'http_baseline' in tasks:
        validate_http_baseline_policy(policy)
    
    if 'port_scan' in tasks:
        validate_port_scan_policy(policy)
    
    if 'template_scan' in tasks:
        validate_template_scan_policy(policy)
    
    # Validate all targets
    for target in targets:
        # All targets must pass build_plan validation
        plan = build_plan(policy, target)
        
        # HTTP-specific validation for http_baseline and template_scan
        if 'http_baseline' in tasks or 'template_scan' in tasks:
            if '://' in target:
                validate_http_target(policy, target)


def execute_task(policy, target, task_type):
    """Execute a single task for a target.
    
    Args:
        policy: Policy dict
        target: Target URL/IP
        task_type: Task type to execute
        
    Returns:
        Dict with task result including task_type discriminator
    """
    try:
        if task_type == 'http_baseline':
            from yf_tools.http_baseline import inspect
            result = inspect(policy, target)
        elif task_type == 'port_scan':
            from yf_tools.nmap_baseline import scan
            result = scan(policy, target)
        elif task_type == 'template_scan':
            from yf_tools.nuclei_scan import execute_scan
            result = execute_scan(policy, target)
        else:
            raise ValueError(f'unknown task type: {task_type}')
        
        # Add task_type discriminator
        result['task_type'] = task_type
        return result
        
    except ScopeViolation as exc:
        # Scope violations invalidate the whole run: the policy and the live network disagree,
        # so every remaining task would target something nobody approved. Signal the caller to
        # abort instead of recording a per-task failure and carrying on.
        return {
            'task_type': task_type,
            'kind': f'{task_type}_error',
            'status': 'policy_violation',
            'error': str(exc),
            'abort_chain': True,
            'vulnerability_verified': False
        }
    except PlanError as exc:
        # Task-specific error, don't stop other tasks
        return {
            'task_type': task_type,
            'kind': f'{task_type}_error',
            'status': 'task_error',
            'error': str(exc),
            'vulnerability_verified': False
        }
    except Exception as exc:
        # Unexpected error, still isolate
        return {
            'task_type': task_type,
            'kind': f'{task_type}_error',
            'status': 'task_error',
            'error': f'{type(exc).__name__}: {exc}',
            'vulnerability_verified': False
        }


def run(policy, targets, tasks=None):
    """Execute unified assessment with multiple task types.
    
    Args:
        policy: Policy dict with all required fields
        targets: List of target URLs/IPs
        tasks: List of task types to execute (default: ['http_baseline'])
        
    Returns:
        Dict with:
        - kind: 'unified_assessment_run' or 'http_assessment_run' (backward compat)
        - status: 'completed', 'completed_with_errors', 'paused_backpressure', 'window_expired'
        - results: List of task results with task_type discriminator
        - task_counts: Per-type execution counts
        - failed_count: Total failed tasks
        - unprocessed_count: Count of tasks not executed
    """
    # Default to http_baseline only for backward compatibility
    if tasks is None:
        tasks = ['http_baseline']
    
    # Validate before execution
    validate(policy, targets, tasks)
    
    results = []
    next_start = None
    interval = 1 / policy['requests_per_second']
    task_counts = {task: 0 for task in tasks}
    
    # Total operations = targets × tasks
    total_operations = len(targets) * len(tasks)
    operations_done = 0
    
    # Execute tasks: for each target, run all task types sequentially
    for target_index, target in enumerate(targets):
        for task_type in tasks:
            # Rate limiting
            now = time.monotonic()
            if next_start is not None and now < next_start:
                time.sleep(next_start - now)
                now = next_start
            
            # Check window before each task
            try:
                check_window(policy)
            except PlanError:
                unprocessed = total_operations - operations_done
                kind = 'http_assessment_run' if tasks == ['http_baseline'] else 'unified_assessment_run'
                return {
                    'kind': kind,
                    'status': 'window_expired',
                    'results': results,
                    'task_counts': task_counts,
                    'unprocessed_count': unprocessed
                }
            
            next_start = now + interval
            
            # Execute task
            result = execute_task(policy, target, task_type)
            result['target_index'] = target_index
            results.append(result)
            task_counts[task_type] += 1
            operations_done += 1

            # A scope violation stops the chain: continuing would scan unapproved addresses.
            if result.get('abort_chain'):
                unprocessed = total_operations - operations_done
                kind = 'http_assessment_run' if tasks == ['http_baseline'] else 'unified_assessment_run'
                return {
                    'kind': kind,
                    'status': 'aborted_policy',
                    'results': results,
                    'task_counts': task_counts,
                    'unprocessed_count': unprocessed,
                    'abort_reason': result.get('error'),
                }
            
            # Check for backpressure (429/503 from HTTP tasks)
            if result.get('http_status') in (429, 503):
                unprocessed = total_operations - operations_done
                kind = 'http_assessment_run' if tasks == ['http_baseline'] else 'unified_assessment_run'
                return {
                    'kind': kind,
                    'status': 'paused_backpressure',
                    'results': results,
                    'task_counts': task_counts,
                    'unprocessed_count': unprocessed
                }
    
    # Calculate aggregate status
    failed_count = sum(
        1 for item in results 
        if item.get('status') not in ('observed', 'completed')
    )
    
    if failed_count > 0:
        status = 'completed_with_errors'
    else:
        status = 'completed'
    
    # Backward compatibility: use http_assessment_run kind when only http_baseline
    kind = 'http_assessment_run' if tasks == ['http_baseline'] else 'unified_assessment_run'
    
    return {
        'kind': kind,
        'status': status,
        'results': results,
        'task_counts': task_counts,
        'failed_count': failed_count,
        'unprocessed_count': 0,
        'vulnerability_verified': False
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', required=True, help='Policy JSON file')
    parser.add_argument('--targets', required=True, help='JSON array of approved URLs/IPs')
    parser.add_argument('--tasks', help='Comma-separated task types (http_baseline,port_scan,template_scan)')
    parser.add_argument('--output', help='new report file; existing files are never overwritten')
    args = parser.parse_args()
    
    try:
        policy = json.loads(Path(args.policy).read_text())
        targets = json.loads(Path(args.targets).read_text())
        
        # Parse tasks if provided
        tasks = None
        if args.tasks:
            tasks = [t.strip() for t in args.tasks.split(',')]
        
        result = run(policy, targets, tasks=tasks)
    except (OSError, ValueError) as exc:
        print(f'assessment_run: invalid input or inactive authorization: {exc}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('assessment_run: interrupted; no automatic retry', file=sys.stderr)
        return 130
    
    if args.output:
        from yf_tools.report_artifact import save
        try:
            artifact = save(args.output, result)
        except (OSError, ValueError):
            print('assessment_run: report publication failed; no automatic scan retry', file=sys.stderr)
            return 3
        print(json.dumps({'report_artifact': artifact}, sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    
    return 0 if result['status'] == 'completed' else 2

if __name__ == '__main__':
    sys.exit(main())
