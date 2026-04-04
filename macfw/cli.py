from __future__ import annotations

import argparse
import os
import pwd
import re
import sys
from pathlib import Path
from textwrap import dedent
from typing import Callable, Mapping, Optional, Sequence, TextIO

from macfw.config import Rule, VALID_FAMILIES
from macfw.manager import MacFwManager, Paths


class UsageError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


class MatchError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class MacFwArgumentParser(argparse.ArgumentParser):
    def exit(self, status: int = 0, message: Optional[str] = None) -> None:
        raise UsageError(status, message or "")

    def error(self, message: str) -> None:
        raise UsageError(2, f"{self.format_usage()}{self.prog}: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = MacFwArgumentParser(prog="macfw", description="A small pf-based firewall manager for macOS.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install")
    install_parser.add_argument("--interface", required=True)

    subparsers.add_parser("uninstall")
    subparsers.add_parser("enable")
    subparsers.add_parser("disable")
    subparsers.add_parser("status")
    subparsers.add_parser("reload")

    allow_parser = subparsers.add_parser("allow")
    allow_parser.add_argument("tokens", nargs=argparse.REMAINDER)

    deny_parser = subparsers.add_parser("deny")
    deny_parser.add_argument("tokens", nargs=argparse.REMAINDER)

    delete_parser = subparsers.add_parser("delete")
    delete_parser.add_argument("tokens", nargs=argparse.REMAINDER)

    return parser


def argv_command(argv: Optional[Sequence[str]]) -> str:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return ""
    return argv[0]


def resolve_home() -> Path:
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


def command_requires_sudo(command: str) -> bool:
    return command in {"install", "uninstall", "enable", "disable", "reload", "allow", "deny", "delete"}


def sudo_retry_hint(argv: Optional[Sequence[str]]) -> str:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return "sudo macfw"
    return "sudo macfw " + " ".join(argv)


def ssh_session_warning(env: Mapping[str, str], command: str) -> str:
    if command not in {"enable", "reload", "allow", "deny", "delete"}:
        return ""
    if "SSH_CONNECTION" not in env and "SSH_CLIENT" not in env:
        return ""
    return (
        "warning: running this command from an SSH session may interrupt existing SSH "
        "connections while pf rules are applied"
    )


def rule_usage(command: str) -> str:
    return dedent(
        f"""\
        usage: macfw {command} <port[/proto]> [ipv4|ipv6]
               macfw {command} <port[/proto]> from <source> [ipv4|ipv6]
               macfw {command} proto <proto> [ipv4|ipv6]
               macfw {command} from <source> [to any] [port <port|all>] [proto <proto>] [ipv4|ipv6]

        examples:
          macfw {command} 22/tcp
          macfw {command} 22/tcp ipv6
          macfw {command} 22/tcp from 1.2.3.4
          macfw {command} 22/tcp from any ipv6
          macfw {command} proto icmp ipv4
          macfw {command} from 192.168.0.0/16
          macfw {command} from any to any port 22 proto tcp
        """
    )


def allow_usage() -> str:
    return rule_usage("allow")


def deny_usage() -> str:
    return rule_usage("deny")


def delete_usage() -> str:
    return dedent(
        """\
        usage: macfw delete <port[/proto]> [ipv4|ipv6]
               macfw delete [allow|deny] <port[/proto]> [ipv4|ipv6]
               macfw delete [allow|deny] <port[/proto]> from <source> [ipv4|ipv6]
               macfw delete proto <proto> [ipv4|ipv6]
               macfw delete [allow|deny] from <source> [to any] [port <port|all>] [proto <proto>] [ipv4|ipv6]

        examples:
          macfw delete 22/tcp
          macfw delete deny 22/tcp
          macfw delete 22/tcp ipv6
          macfw delete 22/tcp from 1.2.3.4
          macfw delete 22/tcp from any ipv6
          macfw delete proto icmp ipv4
          macfw delete deny proto icmp6 ipv6
          macfw delete from 192.168.0.0/16
          macfw delete from any to any port 22 proto tcp
        """
    )


def command_help(argv: Sequence[str], parser: argparse.ArgumentParser) -> str | None:
    if not argv:
        return None
    if argv[0] in {"-h", "--help"}:
        return parser.format_help()
    if len(argv) == 2 and argv[1] in {"-h", "--help"}:
        if argv[0] == "allow":
            return allow_usage()
        if argv[0] == "deny":
            return deny_usage()
        if argv[0] == "delete":
            return delete_usage()
    return None


def parse_rule_tokens(tokens: Sequence[str], action: str, *, command_name: str) -> Rule:
    if not tokens:
        raise UsageError(2, command_usage(command_name))

    if tokens[0] == "from":
        return parse_from_rule(tokens, action=action, command_name=command_name)

    if tokens[0] == "proto":
        if len(tokens) < 2:
            raise UsageError(2, command_usage(command_name))
        proto = tokens[1]
        family = parse_family(tokens[2:])
        return Rule(action=action, source="any", port="all", proto=proto, family=family)

    spec = tokens[0]
    source = "any"
    remainder = list(tokens[1:])
    if remainder[:1] == ["from"]:
        if len(remainder) < 2:
            raise UsageError(2, command_usage(command_name))
        source = remainder[1]
        remainder = remainder[2:]
    family = parse_family(remainder)
    port, proto = parse_port_proto(spec)
    return Rule(action=action, source=source, port=port, proto=proto, family=family)


def parse_family(tokens: Sequence[str]) -> str:
    if not tokens:
        return "both"
    if len(tokens) == 1 and tokens[0] in {"ipv4", "ipv6"}:
        return tokens[0]
    if len(tokens) == 2 and tokens[0] == "family" and tokens[1] in VALID_FAMILIES:
        return tokens[1]
    raise UsageError(2, "error: invalid family selector\n")


def parse_port_proto(spec: str) -> tuple[str, str]:
    if "/" in spec:
        port, proto = spec.split("/", 1)
        return normalize_port_text(port), proto
    return normalize_port_text(spec), "tcp"


def normalize_port_text(port: str) -> str:
    if port == "all":
        return port
    int(port)
    return port


def parse_from_rule(tokens: Sequence[str], action: str, *, command_name: str) -> Rule:
    if len(tokens) < 2:
        raise UsageError(2, command_usage(command_name))

    source = tokens[1]
    port = "all"
    proto = "any"
    family = "both"
    index = 2

    while index < len(tokens):
        token = tokens[index]
        if token == "to":
            if index + 1 >= len(tokens):
                raise UsageError(2, command_usage(command_name))
            destination = tokens[index + 1]
            if destination not in {"any", "self"}:
                raise UsageError(2, "error: only 'to any' and 'to self' are supported\n")
            index += 2
            continue
        if token == "port":
            if index + 1 >= len(tokens):
                raise UsageError(2, command_usage(command_name))
            port = normalize_port_text(tokens[index + 1])
            index += 2
            continue
        if token == "proto":
            if index + 1 >= len(tokens):
                raise UsageError(2, command_usage(command_name))
            proto = tokens[index + 1]
            index += 2
            continue
        if token == "family":
            if index + 1 >= len(tokens):
                raise UsageError(2, command_usage(command_name))
            family = tokens[index + 1]
            index += 2
            continue
        if token in {"ipv4", "ipv6"}:
            family = token
            index += 1
            continue
        raise UsageError(2, f"error: unrecognized rule token: {token}\n")

    return Rule(action=action, source=source, port=port, proto=proto, family=family)


def compatibility_tokens(command: str, tokens: Sequence[str]) -> tuple[str, list[str]]:
    if command != "allow":
        return command, list(tokens)
    if not tokens:
        return command, list(tokens)
    if tokens[0] == "add":
        return "allow", list(tokens[1:])
    if tokens[0] == "remove":
        return "delete", list(tokens[1:])
    return "allow", list(tokens)


def delete_tokens(tokens: Sequence[str]) -> tuple[str, list[str]]:
    if tokens and tokens[0] in {"allow", "deny"}:
        return tokens[0], list(tokens[1:])
    return "", list(tokens)


def command_usage(command_name: str) -> str:
    if command_name == "allow":
        return allow_usage()
    if command_name == "deny":
        return deny_usage()
    return delete_usage()


def main(
    argv: Optional[Sequence[str]] = None,
    *,
    home: Optional[Path] = None,
    root: Optional[Path] = None,
    stdout: Optional[TextIO] = None,
    geteuid: Optional[Callable[[], int]] = None,
    env: Optional[Mapping[str, str]] = None,
) -> int:
    output = stdout or sys.stdout
    root_path = root or Path("/")
    get_euid = geteuid or os.geteuid
    live_env = env or os.environ
    command_name = argv_command(argv)
    parser = build_parser()
    raw_argv = list(sys.argv[1:] if argv is None else argv)

    help_text = command_help(raw_argv, parser)
    if help_text is not None:
        print(help_text, file=output, end="" if help_text.endswith("\n") else "\n")
        return 0

    try:
        args = parser.parse_args(argv)
    except UsageError as exc:
        if exc.status == 0:
            return 0
        if exc.message:
            print(exc.message, file=output, end="" if exc.message.endswith("\n") else "\n")
        if root_path == Path("/") and command_requires_sudo(command_name) and get_euid() != 0:
            print(f"hint: macfw {command_name} usually requires sudo", file=output)
        return exc.status

    effective_command = args.command
    rule_tokens: list[str] = []
    target_action = ""
    if args.command in {"allow", "deny", "delete"}:
        effective_command, rule_tokens = compatibility_tokens(args.command, args.tokens)
        if args.command == "delete":
            target_action, rule_tokens = delete_tokens(rule_tokens)
        else:
            target_action = effective_command

    parsed_rule: Rule | None = None
    if args.command in {"allow", "deny", "delete"}:
        try:
            parse_action = target_action or "allow"
            parsed_rule = parse_rule_tokens(rule_tokens, action=parse_action, command_name=effective_command)
        except UsageError as exc:
            if exc.message:
                print(exc.message, file=output, end="" if exc.message.endswith("\n") else "\n")
            if root_path == Path("/") and command_requires_sudo(effective_command) and get_euid() != 0:
                print(f"hint: macfw {effective_command} usually requires sudo", file=output)
            return exc.status

    if root_path == Path("/") and command_requires_sudo(effective_command) and get_euid() != 0:
        print(f"error: macfw {effective_command} requires sudo", file=output)
        print(f"hint: try: {sudo_retry_hint(argv)}", file=output)
        return 1

    warning = ssh_session_warning(live_env, effective_command)
    if warning:
        print(warning, file=output)

    paths = Paths(home=home or resolve_home(), root=root_path)
    manager = MacFwManager(paths)
    try:
        if args.command == "install":
            manager.install(args.interface)
            print(f"installed macfw on interface {args.interface}", file=output)
            return 0

        if args.command == "uninstall":
            manager.uninstall()
            print("uninstalled macfw", file=output)
            return 0

        if args.command == "enable":
            manager.enable()
            print("macfw enabled", file=output)
            return 0

        if args.command == "disable":
            manager.disable()
            print("macfw disabled", file=output)
            return 0

        if args.command == "reload":
            if manager.status()["enabled"]:
                manager.enable()
            else:
                manager.disable()
            print("macfw reloaded", file=output)
            return 0

        if args.command in {"allow", "deny", "delete"}:
            assert parsed_rule is not None
            rule = parsed_rule
            if effective_command in {"allow", "deny"}:
                manager.add_rule(rule)
                print(f"added {format_rule_summary(rule)}", file=output)
                return 0
            delete_action = target_action or None
            matches = manager.find_matching_rules(rule, action=delete_action)
            if not matches:
                print(f"error: no matching rule found for {format_rule_summary(rule)}", file=output)
                return 2
            if len(matches) > 1:
                raise MatchError(ambiguous_delete_message(rule))
            manager.remove_rule(matches[0])
            print(f"removed {format_rule_summary(matches[0])}", file=output)
            return 0

        if args.command == "status":
            status = manager.status()
            state = "enabled" if status["enabled"] else "disabled"
            pf_enabled = status["pf_enabled"]
            if pf_enabled is None:
                pf_state = "unknown (run with sudo macfw status to verify live pf state)"
            else:
                pf_state = "enabled" if pf_enabled else "disabled"
            print(f"macfw: {state}", file=output)
            print(f"pf: {pf_state}", file=output)
            print(f"interface: {status['interface']}", file=output)
            print_status_rules(status["rules"], output)
            return 0
    except FileNotFoundError:
        print("macfw is not installed", file=output)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=output)
        return 2
    except MatchError as exc:
        print(f"error: {exc.message}", file=output)
        return 2

    return 1


def format_rule_summary(rule: Rule) -> str:
    summary = f"from {rule.source} to self port {rule.port} proto {rule.proto}"
    if rule.family != "both":
        summary += f" family {rule.family}"
    return summary


STATUS_RULE_RE = re.compile(
    r"^(?P<action>allow|deny) from (?P<source>.+?) to self(?: port (?P<port>\S+))? proto (?P<proto>\S+?)(?: family (?P<family>ipv4|ipv6))?$"
)


def status_rule_rows(lines: Sequence[str]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for line in lines:
        parsed = parse_status_rule(line)
        if parsed is None:
            rows.append((line, "", ""))
            continue
        rows.extend(parsed)
    return rows


def parse_status_rule(line: str) -> list[tuple[str, str, str]] | None:
    match = STATUS_RULE_RE.match(line)
    if not match:
        return None

    action = "ALLOW IN" if match.group("action") == "allow" else "DENY IN"
    source = match.group("source")
    port = match.group("port") or "all"
    proto = match.group("proto")
    family = match.group("family") or "both"

    families = ["ipv4", "ipv6"] if family == "both" and source == "any" else [family]
    return [
        (
            format_to_label(port, proto, row_family),
            action,
            format_from_label(source, row_family),
        )
        for row_family in families
    ]


def format_to_label(port: str, proto: str, family: str) -> str:
    if port == "all" and proto == "any":
        label = "Anywhere"
    elif port == "all":
        label = proto
    elif proto == "any":
        label = port
    else:
        label = f"{port}/{proto}"

    if family == "ipv6" and proto != "icmp6":
        label += " (v6)"
    return label


def format_from_label(source: str, family: str) -> str:
    if source == "any":
        return "Anywhere (v6)" if family == "ipv6" else "Anywhere"
    if source == "local":
        return "Local"
    if source == "lan":
        return "LAN"
    return source


def print_status_rules(lines: Sequence[str], output: TextIO) -> None:
    rows = status_rule_rows(lines)
    to_width = max(len("To"), *(len(row[0]) for row in rows))
    action_width = max(len("Action"), *(len(row[1]) for row in rows))

    print("rules:", file=output)
    print(f"  {'To'.ljust(to_width)}  {'Action'.ljust(action_width)}  From", file=output)
    for to_label, action, from_label in rows:
        print(f"  {to_label.ljust(to_width)}  {action.ljust(action_width)}  {from_label}", file=output)


def ambiguous_delete_message(rule: Rule) -> str:
    return (
        f"ambiguous delete for {format_rule_summary(rule)}; "
        f"try `macfw delete allow {delete_target_hint(rule)}` or "
        f"`macfw delete deny {delete_target_hint(rule)}`"
    )


def delete_target_hint(rule: Rule) -> str:
    target = port_proto_hint(rule)
    if rule.source != "any":
        target += f" from {rule.source}"
    if rule.family != "both":
        target += f" {rule.family}"
    return target


def port_proto_hint(rule: Rule) -> str:
    if rule.port == "all":
        return f"proto {rule.proto}"
    if rule.proto == "tcp":
        return f"{rule.port}/tcp"
    return f"{rule.port}/{rule.proto}"


if __name__ == "__main__":
    raise SystemExit(main())
