---
name: frontend-api-recon
description: "Map a site's API surface and routes without credentials."
version: 0.1.0
author: "trhhubsd (ARTEX), Hermes Agent"
license: AGPL-3.0
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [recon, api, spa, frontend, pentest]
    category: security
    related_skills: [playwright-cli, hermesyf-authorized-assessment]
---

# Frontend API Recon（前端接口侦察）

无凭据下摸清一个网站/SPA 的完整 API 面：后端 API（path/method/参数/响应）、前端路由、UI 功能触发点。只做侦察，不做漏洞利用。

## When to Use
- 收到一个 SPA/网站，先摸清它的完整 API 面再决定打哪里
- 无账号/无凭据，但想拿到登录后壳层的全部接口清单
- 需要还原前端权限树（角色→菜单→接口映射）做越权分析

不用于：SQLi/XSS/越权/爆破/改包等漏洞挖掘与利用（那些属于评估阶段，见 hermesyf-authorized-assessment）。

## 核心思路：无凭据撑壳

用 mock 撑开前端路由与组件挂载，只录 outbound 请求。后端返回什么不重要，重要的是前端还会发哪些接口。

1. `preload.js` 在 document-start 注入，拦截 `/login` 跳转（Location/history.pushState/href setter/Vue Router beforeEach 全中和）
2. 对登录/权限/menu 等 bootstrap 接口返回结构正确、业务码成功、数据可为空的 mock body（L1 精确 stub / L2 负向修正 / L3 空成功体兜底）
3. 让 SPA 在无后端或 401 下仍渲染登录后页面，触发更多 XHR/fetch/WS/SSE
4. 空数据、空白表格、占位 UI 均属预期——勿为此转向真实登录或漏洞测试

## 两层模型

| 层 | 产出 | 局限 |
|---|---|---|
| 静态（JS bundle） | 全量 endpoint 路径、路由草案、参数字段候选 | 无 HTTP 方法；漏运行时拼接 URL |
| 运行时（活会话） | method + body + 响应 + 动态 URL + WS/SSE | 页面须实际渲染才发请求 |

## 执行流程

按序执行，前一项未完成不进下一 Phase。

```
Phase 0 分类(SPA/MPA) + 建 OUTDIR
  → Phase 1 静态 harvest（★立刻跑★）
  → Phase 1b 参数逆向
  → Phase 2 鉴权三道门 → config.json
  → Phase 3 运行时 + 参数矩阵
  → Phase 4 权限树（必要时）→ 重跑 Phase 3
  → Phase 5 合并报告
```

### Phase 0 — 分类
拉入口 HTML，建 `OUTDIR`（勿改 skill 内 scripts/）。SPA（空壳+`<div id=app>`+chunk）走 Phase 1-5；MPA（SSR+`<form>`）走 spider_mpa.py。

### Phase 1 — 静态 harvest
先复制脚本再跑，禁止手写 extract：

```bash
cp scripts/harvest_static.py scripts/spider_mpa.py OUTDIR/
python3 OUTDIR/harvest_static.py <BASE_URL> OUTDIR
wc -l OUTDIR/api_static.txt OUTDIR/routes.txt; ls OUTDIR/js | wc -l
```

harvest 会：解析 HTML script → webpack/Vite manifest → 下载全部 lazy chunk → 产出 `js/`、`api_static.txt`、`routes.txt`、`chunkmap.txt`。chunk 数 404 须改 harvest 重试，勿手工 curl 逐个 chunk。

**Remix/React Router 站**（`window.__reactRouterManifest`）harvest 会漏——lazy chunk 由 `module:` 字段映射，不走 webpack/Vite manifest，`api_static.txt` 常为 0 行。此时直接拆 manifest 拿路由→chunk 名，再逐个下载 grep。manifest JSON 末尾带 `;`，`split('=',1)[1]` 后要 `rstrip().rstrip(';')` 才能 json.loads。

### Phase 1b — 参数逆向
path 来自 Phase 1；参数字段须单独 recon。锚点扩窗（已知 path 为锚找组包对象）→ 绑定层（表单 submit→transform→API payload）→ 多样本 diff（必填/可选靠 Phase 3 矩阵+diff）。标注 `transport: query|json|form|graphql|encrypted`。

### Phase 2 — 鉴权三道门（写到 config.json）

| 门 | 问题 | 关键词 |
|---|---|---|
| 渲染门 | 如何判断已登录？ | `isLogin`/`getToken`/Cookie/localStorage |
| 拦截器门 | 什么触发跳 `/login`？ | `response_code`/`errno`/axios interceptor |
| 内容门 | 菜单/权限从哪来？ | `menu`/`permission`/`role`/`acl`/`routes` |

禁止把 localStorage 键名当凭据——须从 chunk/请求链确认。出口：结论落 config.json，改 runtime_harvest.js/preload.js。

### Phase 3 — 运行时
config.json 设 `runtimeMode: depth|coverage|both`。depth 用 `runtime_harvest.js`（Puppeteer，遍历 routes）；coverage 用 browser + `preload.js`（document-start 注入，点 Tab/弹窗/表格）。

```bash
cd OUTDIR && npm install && node runtime_harvest.js config.json
```

验证：`window.__API_RECON_PRELOAD__` 存在；业务 path 不回 `/login`。**参数触发矩阵**（必做）：列表首屏/点搜索/高级筛选/新建编辑/批量导出各录一次，diff 多样本。

### Phase 4 — 权限树还原（模块页空白时触发）
每路由仅 bootstrap（如 locale）= 内容门未过。链：`role_permissions`(flat codes) + `permissions/all`(tree) → `getResultTree` → `userRouteAuth[CODE].url`。

```bash
python3 OUTDIR/extract_route_map.py OUTDIR/js OUTDIR/
python3 OUTDIR/build_perm_tree.py OUTDIR/js OUTDIR/ --config OUTDIR/config.json
```

更新 config.json 后重跑 Phase 3。

### Phase 5 — 合并报告
产出：`api_merged.txt`（`METHOD /path [params] [static|runtime|both]`）、`params_merged.json`、`site_map.json`。报告注明 runtimeMode、静态/运行时 API 数、参数置信度、未覆盖模块。

## 脚本清单（scripts/ 是模板，复制到 OUTDIR 按目标改）
- `harvest_static.py` — SPA 静态收割（webpack/Vite chunk manifest 全量下载 + endpoint/route 正则提取）
- `spider_mpa.py` — MPA 爬取（forms/links/inline API）
- `runtime_harvest.js` — 运行时 depth 模式（Puppeteer，遍历 routes 录 XHR/fetch/WS）
- `preload.js` — coverage 模式预加载（跳转中和 + fetch/XHR Hook + mock 分层）
- `extract_route_map.py` / `build_perm_tree.py` — 权限树还原
- `references/reference.md` — grep 配方、config.json 模板、排障

## 关键纪律
- >100KB 的 `index-*.js` 禁止 Read/grep 进上下文，用 OUTDIR 脚本批处理；grep 必须 `| head -20` 或 `-m 5`
- 同一 grep/命令失败 ≥2 次就换策略，不硬磕
- 加密/签名参数（`sign`/`data`）→ Hook 加密函数入参（见 references/reference.md D 节）
- 盲区标注局限：JSVMP/WASM/HMAC/mTLS 强校验 → 静态+标注；RSC/Server Actions 不完全可枚举
- **区分前端路由 vs 后端 API**：`/admin/*`、`/dashboard/*` 可能是 React Router 前端路由（不是后端接口）；真实后端 API 前缀可能是 `/__xxx/`、`/__api/` 等非标准前缀。拿到清单后先 curl 一个确认返回 404（SPA fallback）还是 JSON（真后端），别把前端路由当后端接口打。
