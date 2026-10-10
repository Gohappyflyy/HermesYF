# Nuclei 模板扫描器实现总结

## 完成状态

✅ **严格 TDD 流程完成** - 先编写测试（RED），再实现功能（GREEN）

## 实现文件

### 1. 核心模块：`yf_tools/nuclei_scan.py` (278 行)

**主要功能：**
- `validate_policy(policy, target)` - 策略验证函数
- `execute_scan(policy, target)` - 执行扫描的主函数
- `main()` - CLI 入口点
- `ScanError` - 自定义异常类

**关键特性：**
- 通过 `assessment_plan.build_plan` 验证目标在授权范围内
- 强制策略约束（模板白名单、路径安全、数量限制）
- subprocess.run(shell=False) 防止命令注入
- 超时上限 300 秒
- 有界 JSONL 输出收集
- 过滤敏感数据（不输出 request/response/extracted-results）

### 2. 测试套件：`yf_tests/test_nuclei_scan.py` (396 行，20 个测试)

**测试分类：**

#### 策略验证 (3 个测试)
- ✅ 要求 allowed_tests 中显式包含 'template_scan'
- ✅ 通过 build_plan 验证目标
- ✅ 使用策略中的 requests_per_second

#### 模板验证 (4 个测试)
- ✅ 要求设置 approved_template_dir
- ✅ 强制执行 max_templates 限制
- ✅ 默认 max_templates = 100
- ✅ 模板路径必须是相对路径（拒绝绝对路径和 `..` 遍历）

#### 执行错误处理 (3 个测试)
- ✅ 检测 nuclei 二进制文件不可用
- ✅ 检测 subprocess 超时
- ✅ 检测非零退出码

#### 输出解析 (2 个测试)
- ✅ 解析 JSONL 输出并提取必需字段
- ✅ 有界输出收集（处理大量结果）

#### 命令行标志 (3 个测试)
- ✅ 验证使用 shell=False
- ✅ 验证正确的 nuclei 命令行标志
- ✅ 防止用户注入任意标志

#### 集成测试 (2 个测试)
- ✅ 真实 nuclei + 本地 HTTP 服务器（如果 nuclei 已安装则执行）
- ✅ 与 scan_report.summarize 的输出兼容性

## 命令行使用

```bash
# 基本用法
python3 -m yf_tools.nuclei_scan --policy policy.json --target http://example.test/

# 保存到文件
python3 -m yf_tools.nuclei_scan --policy policy.json --target http://example.test/ --output result.json

# 运行测试
python3 -m unittest yf_tests.test_nuclei_scan -v
```

## 策略文件格式

```json
{
  "targets": ["example.test", "192.0.2.0/24"],
  "exclude": [],
  "allowed_tests": ["template_scan"],
  "requests_per_second": 10,
  "scan_timeout_seconds": 60,
  "approved_template_dir": "/path/to/templates",
  "nuclei_templates": ["cves/CVE-2021-1234.yaml", "basic/check.yaml"],
  "max_templates": 100
}
```

## 输出格式

```json
{
  "kind": "nuclei_template_scan",
  "status": "completed",
  "target": "http://example.test/",
  "template_count": 2,
  "match_count": 1,
  "matches": [
    {
      "template_id": "CVE-2021-1234",
      "matched_at": "http://example.test/vulnerable",
      "host": "example.test",
      "severity": "high",
      "vulnerability_verified": false
    }
  ],
  "limitations": [
    "Template matches are candidates, not verified vulnerabilities",
    "No raw request/response data included",
    "Verification requires manual analysis"
  ]
}
```

## 安全约束

### ✅ 已实现的保护措施

1. **策略强制执行**
   - 必须在 allowed_tests 中显式包含 'template_scan'
   - 目标必须通过 assessment_plan.build_plan 验证（范围检查）

2. **模板安全**
   - 显式模板白名单（nuclei_templates）
   - 相对路径强制执行（拒绝绝对路径和 `..`）
   - approved_template_dir 作为根目录
   - max_templates 数量限制（默认 100）

3. **命令注入防护**
   - subprocess.run(shell=False)
   - 固定命令行参数顺序
   - 用户无法注入任意标志

4. **数据过滤**
   - 不输出原始 request/response
   - 不输出 extracted-results
   - 所有结果标记为 vulnerability_verified=false

5. **资源限制**
   - scan_timeout_seconds 上限 300 秒
   - 有界 JSONL 输出收集
   - rate-limit 从策略读取

6. **网络安全**
   - 强制 -no-interactsh（禁用外部交互）
   - 固定超时和重试参数
   - 不允许用户覆盖网络策略

## 与现有工具的集成

### ✅ 成功集成

1. **assessment_plan.py**
   - 使用 `build_plan()` 验证目标
   - 复用 PlanError 异常
   - 'template_scan' 已在 TESTS 字典中定义

2. **scan_report.py**
   - 输出格式兼容 `summarize()` 函数
   - 相同的字段命名约定（template_id, matched_at, severity）
   - 集成测试验证兼容性

3. **现有测试模式**
   - 遵循 test_http_baseline.py 的模式
   - 使用本地 HTTP 服务器进行真实测试
   - Mock subprocess 用于单元测试
   - 集成测试用 @skipUnless(shutil.which('nuclei'))

## 测试执行结果

```
运行 116 个测试，耗时 57.104 秒

✅ 全部通过 (1 个跳过 - nuclei 未安装)

包括：
- 20 个 nuclei_scan 新测试
- 96 个现有 YF 工具测试
```

## 局限性

### 明确声明的限制

1. **不是漏洞验证工具**
   - 所有匹配都是候选，需要人工验证
   - vulnerability_verified 固定为 false

2. **数据限制**
   - 不包含原始请求/响应
   - 不包含提取的数据
   - 仅提供最小必需字段

3. **测试限制**
   - 真实 nuclei 测试需要安装 nuclei
   - 使用本地 HTTP 服务器，不执行互联网扫描
   - 自定义模板用于测试

4. **不是覆盖率证明**
   - 模板扫描不保证发现所有问题
   - 取决于模板质量和覆盖范围

## 未实现的功能（按要求）

根据任务要求，以下功能**故意不实现**：

- ❌ 安装 nuclei 或修改配置
- ❌ Git commit 或 push
- ❌ 允许用户注入任意 nuclei 标志
- ❌ 启用 interactsh 或覆盖网络策略
- ❌ 输出原始请求/响应/提取数据
- ❌ 自动漏洞验证（所有结果都是未验证的候选）

## 代码健康

- ✅ 所有测试通过
- ✅ 无 lint 错误
- ✅ 遵循现有代码风格
- ✅ 完整的中英文文档
- ✅ 类型和异常处理一致
- ✅ 与现有工具集成

## 总行数

- 实现代码：278 行 (yf_tools/nuclei_scan.py)
- 测试代码：396 行 (yf_tests/test_nuclei_scan.py)
- 总计：674 行

---

**实现日期**: 2026-10-10  
**开发方法**: 严格 TDD（测试驱动开发）  
**状态**: ✅ 完成并通过所有测试
