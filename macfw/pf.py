from __future__ import annotations

from textwrap import dedent
from typing import Iterable, List

from macfw.config import Rule

HOOK_BEGIN = "# >>> macfw >>>"
HOOK_END = "# <<< macfw <<<"
HOOK_BLOCK = '\n'.join(
    [
        HOOK_BEGIN,
        'anchor "macfw"',
        'load anchor "macfw" from "/etc/pf.anchors/macfw"',
        HOOK_END,
    ]
)

TRUSTED_V4_SOURCES = [
    "10.0.0.0/8",
    "100.64.0.0/10",
    "172.16.0.0/12",
    "192.168.0.0/16",
]
TRUSTED_V6_SOURCES = [
    "fe80::/10",
    "fd00::/8",
]
LAN_SOURCE_EXPR = "{ ($ext_if:network), " + ", ".join(TRUSTED_V4_SOURCES + TRUSTED_V6_SOURCES) + " }"
LOCAL_DEST_EXPR = "{ 127.0.0.1, ::1 }"


def ensure_pf_hook(contents: str) -> str:
    if HOOK_BEGIN in contents:
        return contents
    stripped = contents.rstrip()
    if stripped:
        return stripped + "\n\n" + HOOK_BLOCK + "\n"
    return HOOK_BLOCK + "\n"


def remove_pf_hook(contents: str) -> str:
    if HOOK_BEGIN not in contents:
        return contents
    start = contents.index(HOOK_BEGIN)
    end = contents.index(HOOK_END) + len(HOOK_END)
    prefix = contents[:start].rstrip()
    suffix = contents[end:].lstrip("\n")
    if prefix and suffix:
        return prefix + "\n" + suffix
    if prefix:
        return prefix + "\n"
    return suffix


def default_status_rules(interface: str) -> list[str]:
    lines = [
        "allow from 127.0.0.1/32 to self port all proto any family ipv4",
        "allow from ::1/128 to self port all proto any family ipv6",
        f"allow from ({interface}:network) to self port all proto any",
    ]
    lines.extend(
        f"allow from {source} to self port all proto any family ipv4"
        for source in TRUSTED_V4_SOURCES
    )
    lines.extend(
        f"allow from {source} to self port all proto any family ipv6"
        for source in TRUSTED_V6_SOURCES
    )
    lines.append("allow from any to self proto icmp6 family ipv6")
    return lines


def render_anchor(interface: str, enabled: bool, rules: Iterable[Rule]) -> str:
    if not enabled:
        return "# macfw disabled\n"

    header = dedent(
        f'''\
        ext_if = "{interface}"
        icmp6_essential = "{{ unreach, toobig, timex, paramprob, neighbrsol, neighbradv, routersol, routeradv }}"

        pass in quick on lo0 all keep state
        pass in quick on $ext_if from {LAN_SOURCE_EXPR} to self keep state
        pass out quick all keep state
        pass in quick on $ext_if inet6 proto ipv6-icmp from any to any icmp6-type $icmp6_essential keep state
        '''
    )

    rendered_rules: List[str] = []
    for rule in sorted(rules, key=rule_sort_key):
        rendered_rules.extend(render_rule(rule))

    tail = "\nblock in log on $ext_if all\n"
    body = "\n".join(rendered_rules)
    if body:
        body += "\n"
    return header + body + tail


def rule_sort_key(rule: Rule) -> tuple[str, str, str, str, str]:
    return (0 if rule.action == "deny" else 1, rule.source, rule.port, rule.proto, rule.family)


def render_rule(rule: Rule) -> list[str]:
    protocols = ["tcp", "udp"] if rule.port != "all" and rule.proto == "any" else [rule.proto]
    rendered = []
    for proto in protocols:
        rendered.append(render_single_rule(rule, proto))
    return rendered


def render_single_rule(rule: Rule, proto: str) -> str:
    action = "pass" if rule.action == "allow" else "block drop"
    interface = "lo0" if rule.source == "local" else "$ext_if"
    source = source_expr(rule.source)
    destination = LOCAL_DEST_EXPR if rule.source == "local" else "self"

    parts = [action, "in", "quick", "on", interface]
    family = family_expr(rule.family)
    if family:
        parts.append(family)
    proto_expr = proto_to_pf(proto)
    if proto_expr:
        parts.extend(["proto", proto_expr])
    parts.extend(["from", source, "to", destination])

    if rule.port != "all" and proto in {"tcp", "udp"}:
        parts.extend(["port", rule.port])

    if rule.action == "allow":
        parts.extend(["keep", "state"])

    return " ".join(parts)


def source_expr(source: str) -> str:
    if source == "any":
        return "any"
    if source == "local":
        return "any"
    if source == "lan":
        return LAN_SOURCE_EXPR
    return source


def family_expr(family: str) -> str:
    if family == "ipv4":
        return "inet"
    if family == "ipv6":
        return "inet6"
    return ""


def proto_to_pf(proto: str) -> str:
    if proto == "any":
        return ""
    if proto == "icmp6":
        return "ipv6-icmp"
    return proto
