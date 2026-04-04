from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List

VALID_ACTIONS = {"allow", "deny"}
VALID_PROTOCOLS = {"any", "tcp", "udp", "icmp", "icmp6"}
VALID_FAMILIES = {"both", "ipv4", "ipv6"}
SPECIAL_SOURCES = {"any", "local", "lan"}
LEGACY_SCOPE_SOURCES = {
    "public": "any",
    "lan": "lan",
    "local-only": "local",
}


@dataclass(frozen=True)
class Rule:
    action: str
    source: str
    port: str
    proto: str
    family: str

    def __post_init__(self) -> None:
        if self.action not in VALID_ACTIONS:
            raise ValueError(f"invalid action: {self.action}")

        normalized_source, inferred_family = normalize_source(self.source)
        normalized_port = normalize_port(self.port)
        normalized_proto = normalize_proto(self.proto)
        normalized_family = normalize_family(self.family, inferred_family, normalized_proto)

        object.__setattr__(self, "source", normalized_source)
        object.__setattr__(self, "port", normalized_port)
        object.__setattr__(self, "proto", normalized_proto)
        object.__setattr__(self, "family", normalized_family)


@dataclass(frozen=True)
class Config:
    interface: str
    enabled: bool
    rules: List[Rule]


def normalize_source(source: str) -> tuple[str, str | None]:
    if source in SPECIAL_SOURCES:
        return source, None

    try:
        network = ipaddress.ip_network(source, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid source: {source}") from exc

    family = "ipv4" if network.version == 4 else "ipv6"
    return str(network), family


def normalize_port(port: str | int) -> str:
    if isinstance(port, int):
        if not (1 <= port <= 65535):
            raise ValueError(f"invalid port: {port}")
        return str(port)

    if port == "all":
        return port

    try:
        value = int(str(port))
    except ValueError as exc:
        raise ValueError(f"invalid port: {port}") from exc

    if not (1 <= value <= 65535):
        raise ValueError(f"invalid port: {port}")
    return str(value)


def normalize_proto(proto: str) -> str:
    if proto not in VALID_PROTOCOLS:
        raise ValueError(f"invalid protocol: {proto}")
    return proto


def normalize_family(family: str, inferred_family: str | None, proto: str) -> str:
    if family not in VALID_FAMILIES:
        raise ValueError(f"invalid family: {family}")

    if proto == "icmp":
        if family == "ipv6":
            raise ValueError("icmp is IPv4-only; use icmp6 for IPv6")
        family = "ipv4"
    elif proto == "icmp6":
        if family == "ipv4":
            raise ValueError("icmp6 is IPv6-only")
        family = "ipv6"

    if inferred_family is None:
        return family

    if family == "both":
        return inferred_family
    if family != inferred_family:
        raise ValueError(f"family {family} does not match source {inferred_family}")
    return family


def default_config(interface: str) -> Config:
    return Config(interface=interface, enabled=False, rules=[])


def migrate_legacy_rule(payload: dict) -> Rule:
    scope = payload["scope"]
    if scope not in LEGACY_SCOPE_SOURCES:
        raise ValueError(f"invalid legacy scope: {scope}")

    return Rule(
        action="allow",
        source=LEGACY_SCOPE_SOURCES[scope],
        port=payload["port"],
        proto=payload["proto"],
        family="both",
    )


def load_config(path: Path) -> Config:
    payload = json.loads(path.read_text())
    rules = []
    for item in payload.get("rules", []):
        if "scope" in item:
            rules.append(migrate_legacy_rule(item))
        else:
            rules.append(Rule(**item))

    return Config(
        interface=payload["interface"],
        enabled=bool(payload["enabled"]),
        rules=rules,
    )


def save_config(path: Path, config: Config) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 2,
        "interface": config.interface,
        "enabled": config.enabled,
        "rules": [asdict(rule) for rule in config.rules],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
