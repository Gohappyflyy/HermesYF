# mihomo 多节点并发探测与轮换

## 为什么用 listeners 而不是逐个切节点

逐个切 `MATCH` 节点：改配置 → reload → 等 3 秒 → 测。100 个节点要 8 分钟。
listeners：一次 reload 开 100+ 个本地端口，每端口绑一个节点，然后并发测，1 分钟出全表。

## 批量开端口并发测

1. **备份配置**（改坏了能回来）
   ```bash
   cp /root/config.yaml /root/config.yaml.bak
   ```

2. **从运行中的实例拿全量节点名**（比解析 YAML 准，YAML 可能有 include/规则集）
   ```bash
   curl -s http://127.0.0.1:9090/proxies/GLOBAL \
     | python3 -c "import json,sys;print('\n'.join(json.load(sys.stdin)['all']))"
   ```

**不要用正则扫 YAML 的 `- name:` 当节点列表**：proxy-groups 的名字混在里面
（`🚀 节点选择`、`🎯 全球直连`…），把它们绑成 listener 会落到 DIRECT 上，探测
结果显示「可用」且出口 IP 是本机——纯假阳性。要么从 `/proxies` 按 `type` 过滤
（`ss|vmess|trojan|anytls|hysteria2`…），要么绑完后丢掉出口 IP 等于本机基线出口
的条目。

3. **生成 listeners 段并追加**
   ```python
   import requests, re
   nodes = [n for n in requests.get("http://127.0.0.1:9090/proxies/GLOBAL").json()["all"]
            if n not in ("DIRECT","REJECT")]
   cfg = open("/root/config.yaml").read()
   cfg = re.sub(r'\nlisteners:\n(?:  .*\n)*', '\n', cfg)      # 清掉旧的
   lines = ["\nlisteners:"]
   for i, n in enumerate(nodes):
       lines += [f"  - name: L{i}", "    type: mixed", f"    port: {11000+i}",
                 "    listen: 127.0.0.1", f"    proxy: {n}"]
   open("/root/config.yaml","w").write(cfg.rstrip()+"\n"+"\n".join(lines)+"\n")
   ```

4. **重载**
   ```bash
   curl -X PUT "http://127.0.0.1:9090/configs?force=true" \
     -H "Content-Type: application/json" -d '{"path":"/root/config.yaml"}'
   ```
   返回 204 即生效；`ss -lnt | grep :110` 确认端口起来了。

5. **每端口当一个独立代理并发测**
   ```python
   P = {"http": f"http://127.0.0.1:{port}", "https": f"http://127.0.0.1:{port}"}
   ```
   `ThreadPoolExecutor(max_workers=25)` 跑 112 个端口约 1 分钟。

6. **收工要拆掉 listeners**：删掉 `listeners:` 段再 reload。留着会让后续「测代理出口」时连到残留端口，误判。

## 把 listeners 当常驻轮换池（长时间任务）

上面的 listeners 不只用来做一次性并发探测。跑长时间任务（撞库、批量枚举）时把它当**逐请求轮换的出口池**：每个请求换一个端口 = 换一个节点 = 换一个 IP，不必等被封了才切。

```python
PORTS = [int(l.split("\t")[0]) for l in open("node_ports.txt")]   # 生成 listeners 时落盘的映射
_i = [0]
_lock = threading.Lock()

def px():
    with _lock:
        _i[0] += 1
        p = PORTS[_i[0] % len(PORTS)]
    return {"http": f"http://127.0.0.1:{p}", "https": f"http://127.0.0.1:{p}"}
```

- **生成时就落盘 `端口<TAB>节点名`**（`node_ports.txt`），脚本读它。事后能对账「哪个端口是哪个节点」，也能把持续 403 的节点单独剔出去，而不是整池重试。
- 开完先抽查 5~6 个端口的出口 IP（`curl -x http://127.0.0.1:PORT https://api.ipify.org`），**必须互不相同**；两个相同 → 节点重复或落到了 DIRECT，池子白做。
- 同一端口可以并发复用（mihomo 自己多路复用），计数器加锁即可。
- 把「是否走池」做成开关（`USE_MIHOMO=1` / `PROXY_PORT` 环境变量）：**同一份脚本不上池就能在兄弟机上直连跑**，不用维护两个版本。
- 任务结束按上面第 6 条拆掉 listeners。

## 切单个节点（临时测试用）

```python
import re, requests
cfg = "/root/config.yaml"
s = open(cfg).read()
open(cfg,"w").write(re.sub(r'^- MATCH,.*$', f'- MATCH,{node_name}', s, flags=re.M))
requests.put("http://127.0.0.1:9090/configs?force=true", json={"path": cfg})
```

- `mode: rule` 下改 `GLOBAL` **无效**——真正决定走向的是 `MATCH` 命中的目标。
- `mode: global` 会把本地 API 请求也代理出去，9090 控制口卡死，改不回来。**不要用 global 模式做切换测试**，改 `MATCH` + reload 就行。

## 组 vs 节点

- `proxy-groups` 里的 `URLTest`/`Selector` 组只含**部分**节点，很可能全是同一机房同一段（「香港优选」20 个节点一条 ASN）。
- 看全量节点用 `GLOBAL` 的 `all`。
- 组内切换：`PUT /proxies/<url-encoded-group> {"name":"<节点>"}`，级联子组会跟着变。
- 切到组里没有的节点会返回 `proxy not exist`（400）。

## 节点可用性诊断顺序

0. **先看节点服务器落在哪个段**：解析真实 IP 后查归属。国内 ISP 段（联通/电信，
   家宽或机房）→ 中转型订阅，海外机器用不了：TCP 通、协议握手超时。做这一步能
   省掉后面所有探测。
1. **TCP**：`timeout 5 bash -c "echo > /dev/tcp/IP/PORT"`
2. **TLS**：`timeout 15 openssl s_client -connect IP:PORT -servername <SNI> -brief`
   - `unexpected eof while reading` = 服务器主动断开。带 SNI、带 ALPN、经其他节点中转都 EOF → **服务器端拒绝，放弃这套订阅**。
3. **mihomo 侧**：`curl "http://127.0.0.1:9090/proxies/<url-encoded>/delay?timeout=8000&url=https://www.gstatic.com/generate_204"`
   - `An error occurred in the delay test` + 日志 `failed to create session: EOF` → 协议不支持或节点挂
4. **协议支持**：anytls / hysteria2 等新协议要新内核。`./mihomo -v` 看版本；旧版对新协议只报 `delay 测试失败`，不报「不支持」，很容易误判成节点全挂。
   要试新内核就下载一份到**独立目录**、用独立路径跑：
   ```bash
   curl -sL -o /tmp/mihomo-new.gz https://github.com/MetaCubeX/mihomo/releases/download/v1.19.15/mihomo-linux-amd64-v1.19.15.gz
   gunzip -f /tmp/mihomo-new.gz && chmod +x /tmp/mihomo-new && /tmp/mihomo-new -v
   ```
   **绝不 `mv` 覆盖用户原有的二进制**（`/root/mihomo` 这类）。用户的是自编译版，可能带定制或与现网配置配套；
   测试完把下载的那份删掉。用户会直接要求「把下载的删了，用我原来的」——不要让他说第二遍。

## DNS 陷阱（fake-ip）

**先查系统 DNS 有没有被主实例劫持**——这是「新订阅节点全灭」的头号假象来源：
```bash
cat /etc/resolv.conf            # 主实例的 dns.listen 若被写进这里，系统解析全走它
getent hosts <节点域名>          # 返回 198.18.x 就是 fake-ip，不是真实地址
```
主 mihomo 用 fake-ip 时会把**系统级**域名解析吐成 `198.18.x`；新起的测试实例（自己的 DNS 未配置）
解析节点域名就拿到假地址，连接全 timeout —— 看起来像「节点全挂」，实际节点好得很。
判定：`dial tcp 198.18.0.x:PORT` 出现在日志里，就是这个问题，与节点无关。
修法二选一：
- 给测试实例配独立 DNS：`dns: {enable: true, enhanced-mode: redir-host, nameserver: [1.1.1.1, 8.8.8.8]}`
- 或直接把 `server:` 换成真实 IP（最稳），SNI 保持原域名

订阅配置自身带 fake-ip 时：
```yaml
dns:
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
```

- 节点域名被解析成 `198.18.x`，`getent hosts` / `dig` 返回假地址，**不代表节点挂了**。
- 判断真伪：TCP 直连真实 IP 若是通的，而 mihomo 里节点连不上 → 把 `enhanced-mode` 改成 `redir-host` 再 reload。
- 查真实 IP（绕过本地 fake-ip）：
  ```bash
  curl -s "https://1.1.1.1/dns-query?name=<domain>&type=A" -H "accept: application/dns-json"
  ```

## 起独立实例做测试，不要动主进程

改端口 + 独立目录，避免影响正在跑的流量：
```bash
sed -i 's/^port: 7890/port: 7895/; s/^socks-port: 7891/socks-port: 7896/; s/^mixed-port: 7893/mixed-port: 7897/; s|external-controller: .*|external-controller: "127.0.0.1:9095"|' config.yaml
```
然后用 `-d <新目录> -f config.yaml` 起，测完 kill。二进制默认沿用用户那份；
要换内核也是在新目录放副本（见上面「节点可用性诊断顺序」第 4 条），不动原文件。

## 进程管理坑

`pgrep -f <关键字>` / `pkill -f <关键字>` 会匹配到**执行这条命令的 shell 自己**（命令行里就含那个关键字），表现为命令被 SIGTERM 自杀。要么用精确 PID，要么让关键字不出现在命令行里（用 `pkill -x mihomo` 按进程名）。
