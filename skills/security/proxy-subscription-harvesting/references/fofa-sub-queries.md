# FOFA 找代理订阅：语法库与命中率

前提：已有可用的 FOFA 查询枪（见 `seagull-pentest` 的 `scripts/fofa_client.py`）。

## 高命中语法

| 语法 | 实测命中 | 拿到什么 | 备注 |
|---|---|---|---|
| `body="proxies:" && body="type: vless"` | 579 | **直出 Clash YAML** | 首选。curl 下来直接 yaml 解析，无需猜路径 |
| `body="/api/v1/client/subscribe?token="` | 530 | x-ui 面板首页 | 页面里正则抓 `token=` 再拼 `/api/v1/client/subscribe?token=` |
| `body="subscribe?token=" && body="vless://"` | 1376 | 面板页 + 节点示例 | 噪声多，需过滤 |
| `title="订阅" && body="vless://"` | 1396 | 中文机场面板 | 同上 |
| `body="vless://" && body="vmess://"` | 17816 | 泛命中 | 只用来摸规模，不适合直接抓 |
| `body="dmxlc3M6Ly8"` | 21 | base64 订阅页 | vless:// 的 base64 前缀；命中少且多为 HTML 生成器 |

## 从面板页提取订阅 URL

面板首页通常直接展示订阅链接，正则：

```python
SUB_RE = re.compile(r'(?:https?://[^\s"\'<>\\]+)?/(?:api/v1/client/)?(?:sub|subscribe)(?:\?|/)[^\s"\'<>\\]{0,120}token=[A-Za-z0-9_\-]{6,}', re.I)
TOKEN_RE = re.compile(r'token=([A-Za-z0-9_\-]{6,})')
```

抓到相对路径后拼回 `scheme://host`。

## 判定「是订阅」的唯一标准

body 能 `yaml.safe_load` 成 dict 且 `cfg['proxies']` 是非空 list、每项有 `server`。
命中关键词、HTTP 200、Content-Type 全都不算数。

## 典型噪声

- 「VPN Config Manager」类生成器页：HTML 里塞一条 `vless://` 示例，30KB 页面，解析不出 proxies。
- 失效订阅：返回 base64 但解出来是 `ss://...@127.0.0.1:1111#套餐流量已用完！` 这种占位节点——看到 127.0.0.1 直接丢。
- 同一份聚合订阅挂在多个域名下（`subf.*` 与 `0xaa.*` 内容完全一致），按 proxies 数量 + 首节点 hash 去重。
