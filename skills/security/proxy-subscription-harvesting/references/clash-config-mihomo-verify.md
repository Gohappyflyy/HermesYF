# 用独立 mihomo 实例验证机场订阅（Clash YAML）

适用：拿到一份**别人家的完整 Clash 配置**（客户订阅、越权拉到的订阅、聚合站直出 YAML），要证明「这套节点真能上网」并交出可复测的东西。判据是出口 IP，不是 HTTP 200，也不是节点数量。

## 0. 为什么不能直接用这份 YAML

机场下发的 YAML 是**它自己客户端的完整配置**：里面自带 `port: 7890 / socks-port / mixed-port / dns.listen / external-controller: 127.0.0.1:9090 / rules`。直接餵给本机 mihomo 会和正在跑的代理抢端口、抢 DNS 监听，把用户自己的网络搞挂。只取 `proxies:` 段，其余全部自己写。

## 1. 只抽 proxies 段

```python
import re
src = open('sub.yml', encoding='utf-8', errors='ignore').read()
lines = src.splitlines()
start = end = None
for i, l in enumerate(lines):
    if l.strip() == 'proxies:' and start is None:
        start = i
    elif start is not None and l and not l.startswith((' ', '-')) and not l.startswith('\t'):
        end = i; break
block = '\n'.join(lines[start:end or len(lines)])
names = re.findall(r'name:\s*"?([^",\n]+)"?', block)
```

从 `proxies:` 起，到**下一个顶格非列表行**为止。不要用 yaml 库去改结构再 dump——节点里常带 `alpn: [h2, http/1.1]` 这类内联数组和中文名，重排会破坏格式；原文照抄最稳。

## 2. 生成最小测试配置

```yaml
mixed-port: 7899
socks-port: 7898
allow-lan: false
mode: rule
log-level: warning
external-controller: 127.0.0.1:9099
dns:
  enable: true
  listen: 127.0.0.1:5336
  nameserver:
    - 223.5.5.5
    - 119.29.29.29
<原样贴入的 proxies 段>
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - <每一个节点名，全部列进来>
rules:
  - MATCH,PROXY
```

**端口、DNS 监听、controller 三样全部换掉**（这里是 7898/7899/9099/5336），和本机常驻代理错开。

## 3. 起实例（独立目录，别污染主配置）

```bash
mkdir -p ./mh && cp test_cfg.yaml ./mh/config.yaml
(cd mh && /root/mihomo -d . -f config.yaml > mh.log 2>&1 &)
sleep 4; tail -5 mh/mh.log     # 看到 "Initial configuration complete" 才算起来
```

## 4. 验出口（唯一判据）

```bash
curl -s -m 12 --socks5-hostname 127.0.0.1:7898 https://api.ip.sb/ip
curl -s -m 12 --socks5-hostname 127.0.0.1:7898 "http://ip-api.com/json/?fields=country,city,isp,query"
```

- 用 `--socks5-hostname`（DNS 走代理），别用 `--socks5`。
- `api.ipify.org` / `ipinfo.io` 常 429/被墙，`api.ip.sb/ip` + `ip-api.com` 是无 key 最稳的一对。
- 记录：出口 IP、国家/城市、ISP、时间。汇报里只写这条，不写「节点数 103」。

## 5. 切节点（证明整个池子不是只有一个出口）

```bash
curl -s http://127.0.0.1:9099/proxies/PROXY | python3 -c \
  "import json,sys;d=json.load(sys.stdin);print(d['now']);print(d['all'][:10])"
curl -s -X PUT http://127.0.0.1:9099/proxies/PROXY \
  -H 'Content-Type: application/json' -d '{"name":"美国05"}'
# 204 = 切换成功；400 "proxy not exist" = 该名字没进 proxy-groups
```

切换后再打一次出口 IP，变了才算池子是真的。

## 6. 清理（别把用户的代理搞挂）

```bash
ps -eo pid,args | grep -E "mihomo -d \./mh" | grep -v grep | awk '{print $1}' | xargs -r kill
```

- **绝对不要** `pkill -x mihomo` / `pkill -f mihomo`：用户的本机代理跑的是同一个二进制名，会被一起杀掉断网。测试实例的命令行特征只有 `-d ./mh`（或 `-d <你的目录>`），按这个匹配 PID 再 kill。
- 杀完确认主进程还在：`ps -eo pid,args | grep Sxrconfig`（或用户实际的主配置文件名）。

## 7. 交付形态

一个 tar.gz 里放：每份订阅的原始 YAML（按账号/套餐命名）、元数据 JSON（账号、token、uuid、总量/已用、订阅 HTTP 码与字节数）、可直接跑的 `test_cfg.yaml`、以及一份 `VERIFICATION.txt`（提取方式 + 实测出口 + 复测命令）。

同时在正文写清边界：**能拉订阅 ≠ 能改额度**。额度以订阅响应头为准：

```bash
curl -sD- -o /dev/null "https://<sub-host>/clash/<pid>/<token>/" | grep subscription-userinfo
# upload/download/total/expire 四个数才是权威；面板桥接 API 回读的 transfer_enable 可能只是镜像表
```

## 坑

- **proxy-groups 里只放前 N 个节点**：切到没进组的名字会 400 `proxy not exist`，看起来像节点坏了，其实是自己漏了。要么全放，要么只用 `all` 里出现过从名单。
- **机场 YAML 顶层 `port:` 是它客户端的**，照抄会把本机端口占掉；只取 `proxies:`。
- **节点名含中文/空格**：JSON body 里按原样传，别自己去空格或转拼音。
- **一个订阅里所有节点出口相同**是正常的（同一落地的不同端口），要证明「池子可用」得切到另一个地区的节点再验一次。
