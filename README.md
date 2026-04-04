# macfw

`macfw` is a small `pf` wrapper for macOS with a `ufw`-like workflow:

- `macfw install --interface en1`
- `macfw allow 22/tcp`
- `macfw deny 22/tcp ipv6`
- `macfw enable`
- `macfw status`
- `macfw disable`
- `macfw uninstall`

It manages a dedicated `pf` anchor at `/etc/pf.anchors/macfw` and a user config at `~/.config/macfw/config.json`.

## Default policy

- loopback traffic is always allowed
- LAN inbound traffic is always allowed
- Tailscale-style `100.64.0.0/10` traffic is treated as trusted private network traffic
- outbound traffic is always allowed
- public inbound traffic is blocked unless you explicitly allow a port

## Install the CLI

The executable lives at `~/.local/bin/macfw` and loads the project from `~/tools/macfw`.

## Rule model

`macfw` manages inbound rules with one simple idea:

- `from <source>`: who may connect
- `port <port|all>`: which local port is reachable
- `proto <proto>`: which protocol is allowed
- `family <both|ipv4|ipv6>`: which IP family applies

There is no separate `public/lan/local-only` mode anymore. The default policy is:

- always allow loopback
- always allow LAN/private/Tailscale-style traffic
- always allow outbound traffic
- block public inbound traffic unless you add an explicit allow rule

## Common commands

```bash
macfw install --interface en1
macfw allow 22/tcp
macfw allow 22/tcp ipv6
macfw allow 22/tcp from 1.2.3.4
macfw allow proto icmp ipv4
macfw allow from 192.168.0.0/16
macfw deny 22/tcp ipv6
macfw deny 22/tcp from 2001:db8::1
macfw allow from any to any port 22 proto tcp
macfw status
macfw enable
macfw disable
macfw delete 22/tcp
macfw delete deny 22/tcp ipv6
macfw delete from 192.168.0.0/16
macfw uninstall
```

## Rule examples

```bash
# allow any IPv4+IPv6 source to reach local TCP/22
macfw allow 22/tcp

# allow only IPv6 source traffic to local TCP/22
macfw allow 22/tcp ipv6

# allow only a specific source to reach local TCP/22
macfw allow 22/tcp from 1.2.3.4
macfw allow 22/tcp from 2001:db8::1

# allow IPv4 ICMP (for example ping)
macfw allow proto icmp ipv4

# allow a specific subnet to reach any local port/protocol
macfw allow from 192.168.0.0/16

# explicitly deny IPv6 TCP/22
macfw deny 22/tcp ipv6

# explicit full form
macfw allow from any to any port 22 proto tcp
```

## Delete matching behavior

- `macfw delete ...` removes `allow` rules by default
- `macfw delete deny ...` removes `deny` rules
- if you omit `ipv4` or `ipv6`, delete uses a broader family match
  - example: `macfw delete 22/tcp` will remove `22/tcp ipv4`, `22/tcp ipv6`, or `22/tcp`
- if you specify `ipv4` or `ipv6`, delete uses exact family matching
  - example: `macfw delete 22/tcp ipv6` does not remove a broader `22/tcp` rule

## Status output

`macfw status` shows the effective allow list that `macfw` manages:

- built-in trusted ranges such as loopback, your active interface network, RFC1918 private IPv4 ranges, `100.64.0.0/10`, `fe80::/10`, and `fd00::/8`
- your own explicit allow rules
- the final default deny for public inbound traffic

If `pf` shows as `unknown`, that means the command could not read live `pfctl` state with the current privileges. Run `sudo macfw status` to verify the actual live PF state.

## Install and uninstall behavior

- `install` backs up the current `/etc/pf.conf`, injects a `macfw` anchor hook, creates `/etc/pf.anchors/macfw`, and writes `~/.config/macfw/config.json`
- `uninstall` removes the `macfw` anchor, restores the original `/etc/pf.conf` backup, and removes the macfw config and state files

## Notes

- Use `sudo` for commands that touch `/etc` or load `pf`, for example `sudo ~/.local/bin/macfw install --interface en1`
- `status` works without `sudo`, but live `pf` state may still require `sudo`
- changing CLI code under `~/tools/macfw` takes effect immediately because `~/.local/bin/macfw` imports the project directly; only `enable` or `reload` pushes rules into live `pf`
