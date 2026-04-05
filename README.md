# macfw

`macfw` is a small `pf`-based firewall manager for macOS with a `ufw`-like CLI.

A `ufw`-like firewall CLI for macOS.

Built for Macs that behave more like servers, especially in IPv6-exposed environments.

[Why](#why-this-exists) • [Quick Start](#quick-start) • [Installation](#install) • [Common Commands](#common-commands) • [Rule Model](#rule-model) • [Default Policy](#default-policy)

[![PyPI version](https://img.shields.io/pypi/v/macfw)](https://pypi.org/project/macfw/)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![macOS](https://img.shields.io/badge/platform-macOS-black)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![English | 中文](https://img.shields.io/badge/docs-English%20%7C%20%E4%B8%AD%E6%96%87-blue)](./README.zh-CN.md)

It is designed for one common use case:

- keep loopback, LAN, and trusted private ranges reachable
- keep outbound traffic open
- deny public inbound traffic by default
- allow or deny explicit inbound exceptions with a short CLI

In practice, you can think of it as:

- a macOS firewall CLI
- a `ufw`-like firewall tool for macOS
- a simple way to manage public inbound exposure on a Mac that behaves more like a server than a personal laptop

## Why this exists

`macfw` exists to solve a gap that becomes obvious in IPv6-heavy home lab and self-hosting environments.

Many people now run a Mac, especially a Mac mini, as a small always-on server for tools, automation, coding agents, model runtimes, remote access, or NAS-like tasks. A particularly important example is people running OpenClaw on a Mac mini as a long-lived agent host. In that role, the machine is no longer just a daily personal computer. It starts behaving more like a Linux VPS, a home server, or a small self-hosted node that needs controlled inbound access.

On IPv4 networks, NAT often provides an extra layer between the machine and the public internet. On IPv6 networks, that assumption is much weaker. A Mac can end up directly reachable from the public internet, which means every listening service deserves deliberate review.

macOS does include firewall features, but the built-in experience is mostly app-oriented and GUI-oriented. It is not a close equivalent to the Linux `ufw` workflow many server users expect when they want to answer simple questions such as:

- which inbound ports are currently meant to be reachable from the public internet
- how do I allow only one port
- how do I allow only IPv4 or only IPv6
- how do I remove or deny a rule from the command line

`macfw` is built for that gap. It gives a Mac server or Mac mini a small command-line firewall workflow that feels much closer to `ufw`, while still using macOS `pf` underneath.

## Who this is for

`macfw` is especially meant for people who:

- run OpenClaw or similar always-on agent workloads on a Mac mini
- run a Mac mini or another macOS machine as an always-on server
- use IPv6 and want tighter control over public inbound exposure
- prefer terminal-based rule management over GUI-only firewall tools
- want a simpler mental model similar to `ufw` rather than raw `pf.conf` editing

## Status

`macfw` is currently an early `0.1.x` release. The rule model is usable, but the project should still be treated as a careful admin tool rather than a polished end-user app.

## Requirements

- macOS
- Python 3.9+
- `pfctl`
- `sudo` access for commands that touch `/etc` or load `pf`

This project is for macOS only. It is not intended for Linux, BSD routers, or Windows.

## Install

### Recommended: install from PyPI with `pipx`

`pipx` is the best default for a CLI tool because it keeps the application isolated while still exposing the `macfw` command on your shell `PATH`.

```bash
python3 -m pip install --user pipx
pipx install macfw
macfw --version
```

Upgrade later:

```bash
pipx upgrade macfw
```

### Alternative: install from PyPI with `pip`

If you prefer a plain Python environment instead of `pipx`:

```bash
python3 -m pip install macfw
macfw --version
```

### Development: install from a local clone

```bash
git clone https://github.com/tudoujunha/macfw.git
cd macfw
python3 -m pip install .
```

### Development: install directly from GitHub

```bash
python3 -m pip install git+https://github.com/tudoujunha/macfw.git
```

### Development: isolated CLI install from GitHub with `pipx`

```bash
pipx install git+https://github.com/tudoujunha/macfw.git
```

## Before you start

You need to know which network interface receives the inbound traffic you want to protect.

Common examples:

- Wi-Fi: often `en0` or `en1`
- Ethernet or USB adapters: often another `enX`

Useful commands:

```bash
ifconfig
networksetup -listallhardwareports
route -n get default
```

If you are not sure, check which interface currently has your LAN or public IP address, then use that interface for `macfw install --interface ...`.

## Quick start

Install the managed anchor and choose the network interface to protect:

```bash
sudo macfw install --interface en1
```

Check the current state before enabling anything:

```bash
macfw status
sudo macfw status
```

If you need SSH from the public internet, allow it before enabling the firewall:

```bash
sudo macfw allow 22/tcp
```

Enable the firewall:

```bash
sudo macfw enable
```

Show current state again:

```bash
macfw status
sudo macfw status
```

Disable or uninstall later:

```bash
sudo macfw disable
sudo macfw uninstall
```

## First-time setup checklist

Recommended order:

1. Install the anchor with the correct interface
2. Review the default policy with `macfw status`
3. Add any public inbound exceptions you need, such as `22/tcp`
4. Enable the firewall
5. Open a new test connection from the network you care about
6. Only then close the old session

This matters because enabling `pf` can interrupt an already-established SSH connection.

## Default policy

- allow loopback traffic
- allow inbound traffic from the active interface network
- allow inbound traffic from private RFC1918 IPv4 ranges
- allow inbound traffic from `100.64.0.0/10`
- allow inbound traffic from `fe80::/10` and `fd00::/8`
- allow outbound traffic
- deny public inbound traffic unless a rule explicitly allows it

## Rule model

Each rule answers four questions:

- `from <source>`: who may connect
- `port <port|all>`: which local port is reachable
- `proto <proto>`: which protocol applies
- `family <both|ipv4|ipv6>`: which IP family applies

Supported protocols today:

- `tcp`
- `udp`
- `icmp`
- `icmp6`
- `any`

## Common commands

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

## Common scenarios

Allow public SSH on IPv6 only:

```bash
sudo macfw allow 22/tcp ipv6
```

Allow public DNS on UDP:

```bash
sudo macfw allow 53/udp
```

Allow SSH only from one specific address:

```bash
sudo macfw allow 22/tcp from 203.0.113.10
sudo macfw allow 22/tcp from 2001:db8::10
```

Explicitly block a public IPv6 SSH rule:

```bash
sudo macfw deny 22/tcp ipv6
```

Remove a single matching rule without caring whether it is `allow` or `deny`:

```bash
sudo macfw delete 22/tcp
```

## Delete matching behavior

`delete` uses two matching modes:

- if you specify `allow` or `deny`, deletion is constrained to that action
- if you do not specify an action, `macfw` looks for all matching rules

That means:

- if exactly one rule matches, `delete` removes it even if it is a `deny`
- if multiple rules match, `delete` stops and asks you to disambiguate with `allow`, `deny`, `ipv4`, `ipv6`, or a more specific source

Family matching works like this:

- omit `ipv4` or `ipv6`: broader family match
- specify `ipv4` or `ipv6`: exact family match

Examples:

```bash
# removes 22/tcp, 22/tcp ipv4, or 22/tcp ipv6 if there is only one match
sudo macfw delete 22/tcp

# removes only an IPv6 rule
sudo macfw delete 22/tcp ipv6

# removes only a deny rule
sudo macfw delete deny 22/tcp ipv6
```

## Status output

`macfw status` shows:

- whether `macfw` is enabled
- whether live `pf` is enabled
- which interface is managed
- your user-defined rules first
- built-in trusted defaults
- the final default deny

If `pf` shows as `unknown`, run:

```bash
sudo macfw status
```

## What `install`, `enable`, `reload`, and `disable` do

- `install`: creates the `macfw` anchor, injects the anchor hook into `/etc/pf.conf`, and writes the local config files
- `enable`: writes the active anchor rules, validates the `pf` config, and enables `pf` if needed
- `reload`: rewrites and reloads the anchor using the current config
- `disable`: keeps the config on disk but disables the active `macfw` policy
- `uninstall`: removes the anchor, restores the original `/etc/pf.conf` backup when available, and removes the local config files

## Safety notes

Be careful when enabling or reloading rules over SSH.

- enabling `pf` can drop an already-established SSH session
- a newly opened LAN SSH session should still match the LAN allow rules
- a public SSH session will be dropped unless you explicitly allow it first

If you rely on public SSH access, add the rule before enabling:

```bash
sudo macfw allow 22/tcp
sudo macfw enable
```

If you rely on LAN SSH only, the default trusted LAN rules should permit a newly opened LAN session after the firewall is enabled. An already-established session can still drop when `pf` first becomes active.

## How it works

`macfw` manages:

- a dedicated anchor at `/etc/pf.anchors/macfw`
- a hook in `/etc/pf.conf`
- a user config at `~/.config/macfw/config.json`
- a small state file at `~/.config/macfw/state.json`

`install` backs up the current `/etc/pf.conf` before modifying it. `uninstall` restores the backup when available.

## Limitations

- there is no Homebrew formula yet
- there is no PyPI release yet
- interface detection is not automatic yet
- this tool is focused on inbound filtering on macOS `pf`
- this tool assumes you are comfortable using `sudo` and reading firewall state before enabling changes

## Development

Run the test suite:

```bash
python3 -m unittest discover -s tests -v
```

Run directly from the repository checkout:

```bash
PYTHONPATH=. python3 -m macfw --help
```

For maintainer release steps, see:

- [`docs/publishing.md`](./docs/publishing.md)

## License

MIT
