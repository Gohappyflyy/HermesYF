# ScopeSentry 各资产类型常用 search 字段

| asset_type | 字段 |
|---|---|
| asset | domain, ip, port, service, app, title, statuscode, icon, banner, type, body, header |
| RootDomain | domain, icp, company |
| subdomain | domain, ip, type, value |
| app | name, icp, company, category, description, url, apk |
| mp | name, icp, company, category, description, url |
| UrlScan | url, input, source, resultId, type |
| SensitiveResult | url, sname, body, info, md5 |
| DirScanResult | url, statuscode, redirect, length |
| vulnerability | url, vulname, matched, request, response, level |
| crawler | url, method, body, resultId |
| PageMonitoring | url, hash, diff, response |
| IPAsset | ip, domain, port, service, webServer, app |
| SubdomainTakerResult | domain, value, type, response |

## 各类型可用 filter key

| asset_type | filter key |
|---|---|
| asset | project, port, service, app, icon, statuscode, type, task, tags |
| RootDomain | project, tags |
| subdomain | project, type, task, tags |
| app / mp | project, tags |
| UrlScan | status, tags |
| DirScanResult | status, tags |
| SensitiveResult | status, color, sname, tags |
| crawler | project, task, tags |
| vulnerability | project, level, status, task, tags |
| PageMonitoring / SubdomainTakerResult | tags |
| IPAsset | project, port, service, app |

## search 示例

- `domain==www.example.com && port==443`（全等，走索引）
- `domain=^example.com`（前缀匹配，走索引）
- `ip==192.168.1.1`
- `task=="某任务名"`（精确匹配任务名）
- `level==high`（vulnerability）
- `statuscode==200`（DirScanResult）

需模糊包含时再用 `=`，如 `title=admin`（不走索引，宜配合项目等条件缩小范围）。
