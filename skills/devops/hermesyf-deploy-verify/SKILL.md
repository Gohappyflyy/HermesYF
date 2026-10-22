---
name: hermesyf-deploy-verify
description: Use when 新机部署 HermesYF 后验收 / 部署自检 / 技能记忆没同步。一条命令跑 14 项检查并定位是哪一步没跑完。
---

# HermesYF 新机部署验收

`deploy.sh` 跑完不等于装齐。它中间有 4 段（clone → setup-hermes → install-yufeng → install-blitzstrike），任何一段静默失败，机器看着能用但技能库/记忆/代理是残的。部署完必须跑验收。

## 一条命令

```bash
bash /root/pentest/deploy_check.sh                # 本机
bash /root/pentest/deploy_check.sh <ip>           # 远程（脚本自己 ssh 推过去执行）
```

退出码 0 = 通过，非 0 = FAIL 数。末尾打 `PASS=n FAIL=n WARN=n`。

远程验前先确认免密：`ssh -o ConnectTimeout=8 root@<ip> true`。密码登录的机器手动 `scp` 过去再跑。

## 检查项与 FAIL 对应修复

| 检查 | FAIL 含义 | 修法 |
|---|---|---|
| 仓库 | `/root/HermesYF` 不存在 | deploy.sh 在 clone 阶段断了，看网络/磁盘 |
| 仓库未提交改动 >0 | 只是 WARN | 本地改的要 push，否则新机拿不到 |
| 技能装载数 <300 | `install-yufeng.sh` 没跑或合并失败 | `bash /root/HermesYF/install-yufeng.sh` |
| 技能数 =0 | HERMES_HOME 指错或 `~/.hermes/skills` 没建 | 查 `echo $HERMES_HOME`、确认 profile |
| 记忆 MEMORY/USER 为空 | 记忆初始化没执行 | 同上，重跑 install-yufeng.sh |
| mihomo 进程 | 代理没起 | `cd /root && nohup ./mihomo -d /root -f /root/Sxrconfig.yaml &` |
| 7890 未监听 | mixed-port 没起 | 看 mihomo 日志，别先怀疑节点 |
| 端口池 <50 | 112 个 listeners 没全起 | 配置文件被截断，重新下发 Sxrconfig.yaml |
| 代理出口 IP 空 | 7890 通不了外网 | 节点全挂/订阅过期，换订阅 |
| 工具缺失 | /root/go/bin 没进 PATH | `export PATH=/root/go/bin:$PATH`，或 `ln -sf` 到 /usr/local/bin |

## 出口 IP 必看

验收会打出代理出口 IP。**它和上次记录不一致不一定是错，但必须记下来**——风哥铁律是所有扫描走代理，出口段变了要能说清是哪一跳。如果出口是 `185.220.x.x` 这类 Tor 段，说明当前节点是 Tor 出口，打有 CF/风控的目标会秒被拦，先换节点再干活。

## 坑

- 脚本里**不要**用 `kill -0 $(cat gateway.pid)` 或任何 pgrep-kill 组合判断网关——在网关进程内部执行会被安全策略直接拦掉整条命令（报 "cannot restart/stop the gateway"）。只读检查用 `-S gateway.sock` + 读 `gateway_state.json`。
- `chmod +x` 和脚本执行不要写成一条被拦的命令，分开跑，否则 chmod 也没执行，下一步报 Permission denied。
- 重跑 deploy.sh 会 `git reset --hard`，机器上未提交的改动全丢；改过代码先 push。
