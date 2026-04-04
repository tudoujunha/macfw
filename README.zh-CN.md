[English](./README.md) | 简体中文

# macfw

`macfw` 是一个运行在 macOS 上、基于 `pf` 的小型防火墙管理工具，命令行交互风格参考了 `ufw`。

它主要解决这样一类场景：

- 保留本机、局域网和可信私网的访问能力
- 保持出站流量开放
- 默认拒绝公网入站
- 通过简洁命令按需开放或拒绝特定入站规则

你也可以直接把它理解成：

- 一个 macOS 防火墙命令行工具
- 一个更接近 Linux `ufw` 体验的 macOS 防火墙工具
- 一个专门用来管理 Mac 暴露到公网时入站端口的工具

## 这个工具为什么存在

`macfw` 想解决的，是 IPv6 环境下 macOS 设备直接暴露在公网时，缺少一个足够顺手的命令行防火墙工具的问题。

这类场景在最近越来越常见。很多人会把一台 Mac，特别是 Mac mini，当成一个长期运行的节点来使用，比如部署自动化工具、编码代理、模型运行环境、远程服务，或者把它当成一台小型家用服务器。这里一个非常典型、也非常重要的场景，就是很多人会用 Mac mini 来长期运行 OpenClaw 这类代理工作负载。这个时候，它的角色已经不再只是“日常主力电脑”，而更像一台 Linux VPS、NAS，或者长期在线的小型服务器。

在 IPv4 环境里，很多家庭网络默认还有 NAT 这一层缓冲，设备并不会天然完整暴露到公网。而在 IPv6 环境里，这层保护往往并不存在或者明显弱得多。只要机器在监听端口，这些服务就可能直接面向公网。

macOS 自带的防火墙并不是不能用，但它的主要体验更偏向图形界面和“按应用授权”，不太适合习惯 Linux 服务器工作流的人。很多时候你真正想解决的是这些问题：

- 现在到底有哪些入站端口会暴露到公网
- 我只想开放某一个端口，怎么做
- 我只想开放 IPv4 或只开放 IPv6，怎么做
- 我想从命令行删除、拒绝、查看规则，怎么做

`macfw` 就是为这个空缺做的。它的定位不是替代 macOS 全部网络安全能力，而是给“像服务器一样运行的 Mac”提供一套更接近 `ufw` 的命令行防火墙体验，底层仍然使用 macOS 自带的 `pf`。

## 适合谁

`macfw` 特别适合下面这些使用者：

- 在 Mac mini 上运行 OpenClaw 或类似常驻代理工作负载的人
- 把 Mac mini 或其他 macOS 设备当作长期在线服务器来运行的人
- 在 IPv6 环境下，希望控制公网入站暴露面的人
- 更习惯终端管理，而不是图形界面点选防火墙的人
- 想要一个比直接写 `pf.conf` 更容易理解、又更像 `ufw` 的工作流的人

## 当前状态

`macfw` 目前处于 `0.1.x` 的早期阶段。规则模型已经可用，但它仍然更适合谨慎使用的系统管理工具，而不是已经完全打磨好的终端用户产品。

## 环境要求

- macOS
- Python 3.9+
- `pfctl`
- 能执行 `sudo` 的权限，用于修改 `/etc` 和加载 `pf`

这个项目只面向 macOS，不适用于 Linux、BSD 路由器或 Windows。

## 安装

### 方式一：先克隆仓库，再本地安装

```bash
git clone https://github.com/tudoujunha/macfw.git
cd macfw
python3 -m pip install .
```

### 方式二：直接从 GitHub 安装

```bash
python3 -m pip install git+https://github.com/tudoujunha/macfw.git
```

### 方式三：用 `pipx` 隔离安装 CLI

```bash
pipx install git+https://github.com/tudoujunha/macfw.git
```

安装后可验证：

```bash
macfw --version
```

## 开始前要先确认什么

你需要知道哪个网卡承接了你想保护的入站流量。

常见情况：

- Wi-Fi：通常是 `en0` 或 `en1`
- 有线网卡、USB 网卡：通常是别的 `enX`

可以用这些命令辅助确认：

```bash
ifconfig
networksetup -listallhardwareports
route -n get default
```

如果不确定，就先看当前哪个接口挂着你的局域网 IP 或公网 IP，再把那个名字传给 `macfw install --interface ...`。

## 快速开始

先安装 `macfw` 管理的 anchor，并指定要保护的网卡：

```bash
sudo macfw install --interface en1
```

启用前先看一下当前状态：

```bash
macfw status
sudo macfw status
```

如果你需要公网 SSH，建议在启用防火墙之前先开放规则：

```bash
sudo macfw allow 22/tcp
```

启用防火墙：

```bash
sudo macfw enable
```

再查看一次状态：

```bash
macfw status
sudo macfw status
```

后续如果要关闭或卸载：

```bash
sudo macfw disable
sudo macfw uninstall
```

## 第一次配置建议顺序

建议按这个顺序来：

1. 用正确的网卡执行 `install`
2. 先看 `macfw status`，确认默认策略
3. 先加上你需要的公网例外规则，比如 `22/tcp`
4. 再执行 `enable`
5. 从你真正关心的网络重新开一个新连接测试
6. 确认新连接可用后，再关闭旧连接

这个顺序很重要，因为 `pf` 第一次启用时，已有 SSH 会话可能会被中断。

## 默认策略

- 允许 loopback
- 允许当前活动网卡所在网段的入站
- 允许 RFC1918 私网 IPv4 的入站
- 允许 `100.64.0.0/10` 的入站
- 允许 `fe80::/10` 和 `fd00::/8` 的入站
- 允许全部出站
- 默认拒绝公网入站，除非你显式写了允许规则

## 规则模型

每条规则都在描述四件事：

- `from <source>`：谁可以连进来
- `port <port|all>`：本机哪个端口可达
- `proto <proto>`：协议是什么
- `family <both|ipv4|ipv6>`：作用在哪个 IP 家族上

当前支持的协议：

- `tcp`
- `udp`
- `icmp`
- `icmp6`
- `any`

## 常用命令

```bash
macfw allow 22/tcp
macfw allow 53/udp
macfw allow 22/tcp ipv6
macfw allow 22/tcp from any ipv4
macfw allow 22/tcp from 1.2.3.4
macfw allow 22/tcp from 2001:db8::1
macfw allow proto icmp ipv4
macfw allow from 192.168.0.0/16

macfw deny 22/tcp ipv6
macfw deny 22/tcp from 2001:db8::1

macfw delete 22/tcp
macfw delete 22/tcp ipv6
macfw delete deny 22/tcp ipv6
macfw delete from 192.168.0.0/16
```

## 常见场景

只开放公网 IPv6 的 SSH：

```bash
sudo macfw allow 22/tcp ipv6
```

开放公网 UDP 53：

```bash
sudo macfw allow 53/udp
```

只允许某个具体地址访问 SSH：

```bash
sudo macfw allow 22/tcp from 203.0.113.10
sudo macfw allow 22/tcp from 2001:db8::10
```

显式拒绝公网 IPv6 的 SSH：

```bash
sudo macfw deny 22/tcp ipv6
```

不关心它是 `allow` 还是 `deny`，只要当前只匹配到一条就删掉：

```bash
sudo macfw delete 22/tcp
```

## delete 的匹配逻辑

`delete` 有两种模式：

- 你显式写了 `allow` 或 `deny`：只会删这一类规则
- 你没有写动作：`macfw` 会先找所有匹配规则

具体表现是：

- 如果只匹配到一条规则，那么即使它是 `deny`，也会直接删掉
- 如果匹配到多条规则，`delete` 会停止，并提示你继续细化条件，比如加上 `allow`、`deny`、`ipv4`、`ipv6` 或更具体的来源地址

family 的匹配规则：

- 不写 `ipv4` 或 `ipv6`：按更宽的 family 匹配
- 写了 `ipv4` 或 `ipv6`：按精确 family 匹配

例如：

```bash
# 如果最终只匹配到一条，它会删除 22/tcp、22/tcp ipv4 或 22/tcp ipv6
sudo macfw delete 22/tcp

# 只删除 IPv6 规则
sudo macfw delete 22/tcp ipv6

# 只删除 deny 规则
sudo macfw delete deny 22/tcp ipv6
```

## 状态输出

`macfw status` 会展示：

- `macfw` 是否启用
- 当前 live `pf` 是否启用
- 当前管理的网卡
- 你自己定义的规则（优先显示）
- 内建可信默认规则
- 最终默认拒绝规则

如果 `pf` 显示为 `unknown`，请使用：

```bash
sudo macfw status
```

## `install`、`enable`、`reload`、`disable` 分别做什么

- `install`：创建 `macfw` anchor，在 `/etc/pf.conf` 中注入 hook，并写入本地配置文件
- `enable`：根据当前配置写入 anchor，校验 `pf` 配置，并在需要时启用 `pf`
- `reload`：按当前配置重写并重新加载规则
- `disable`：保留本地配置，但停用当前 `macfw` 防火墙策略
- `uninstall`：移除 anchor，尽量恢复原始 `/etc/pf.conf` 备份，并删除本地配置文件

## SSH 风险提示

如果你是通过 SSH 远程操作，启用或重载规则要格外小心：

- 启用 `pf` 时，已经建立好的 SSH 连接可能会被立刻断开
- 新建的局域网 SSH 连接通常仍然会命中 LAN 放行规则
- 公网 SSH 如果没有提前显式放开，对应连接会被拦掉

如果你依赖公网 SSH，建议先放行，再启用：

```bash
sudo macfw allow 22/tcp
sudo macfw enable
```

如果你只依赖局域网 SSH，那么在默认策略下，启用后新建的局域网 SSH 会话通常仍然可以通过；但启用瞬间，已经建立好的会话仍然可能断开。

## 工作方式

`macfw` 会管理下面这些内容：

- `/etc/pf.anchors/macfw` 中的专用 anchor
- `/etc/pf.conf` 里的 hook
- `~/.config/macfw/config.json` 用户配置
- `~/.config/macfw/state.json` 状态文件

`install` 会在修改 `/etc/pf.conf` 之前先做备份。`uninstall` 在有备份时会恢复原始文件。

## 当前限制

- 还没有 Homebrew formula
- 还没有正式发布到 PyPI
- 还没有自动探测网卡
- 这个工具主要聚焦 macOS `pf` 的入站过滤
- 它默认使用 `sudo` 和系统级防火墙修改，适合愿意自己确认状态的用户

## 开发

运行测试：

```bash
python3 -m unittest discover -s tests -v
```

直接从仓库目录运行：

```bash
PYTHONPATH=. python3 -m macfw --help
```

## 许可证

MIT
