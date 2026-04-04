from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

from macfw.config import Config, Rule, default_config, load_config, save_config
from macfw.pf import default_status_rules, ensure_pf_hook, remove_pf_hook, render_anchor

Runner = Callable[[List[str]], subprocess.CompletedProcess]


@dataclass(frozen=True)
class Paths:
    home: Path
    root: Path

    @property
    def config_dir(self) -> Path:
        return self.home / ".config" / "macfw"

    @property
    def config_path(self) -> Path:
        return self.config_dir / "config.json"

    @property
    def state_path(self) -> Path:
        return self.config_dir / "state.json"

    @property
    def pf_conf_path(self) -> Path:
        return self.root / "etc" / "pf.conf"

    @property
    def anchor_path(self) -> Path:
        return self.root / "etc" / "pf.anchors" / "macfw"

    @property
    def backup_dir(self) -> Path:
        return self.root / "etc" / "macfw.backups"

    @property
    def backup_pf_conf_path(self) -> Path:
        return self.backup_dir / "pf.conf.before-macfw"


def default_runner(command: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def action_priority(action: str) -> int:
    return 0 if action == "deny" else 1


def config_rule_sort_key(rule: Rule) -> tuple[int, str, str, str, str]:
    return (action_priority(rule.action), rule.source, rule.port, rule.proto, rule.family)


def rule_matches(target: Rule, candidate: Rule) -> bool:
    if target.action != candidate.action:
        return False
    if target.source != candidate.source:
        return False
    if target.port != candidate.port:
        return False
    if target.proto != candidate.proto:
        return False
    if target.family == "both":
        return True
    return target.family == candidate.family


def rule_shape_matches(target: Rule, candidate: Rule) -> bool:
    if target.source != candidate.source:
        return False
    if target.port != candidate.port:
        return False
    if target.proto != candidate.proto:
        return False
    if target.family == "both":
        return True
    return target.family == candidate.family


class MacFwManager:
    def __init__(self, paths: Paths, runner: Optional[Runner] = None, live_system: Optional[bool] = None) -> None:
        self.paths = paths
        self.runner = runner or default_runner
        self.live_system = paths.root == Path("/") if live_system is None else live_system

    def install(self, interface: str) -> None:
        self.paths.config_dir.mkdir(parents=True, exist_ok=True)
        self.paths.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        self.paths.backup_dir.mkdir(parents=True, exist_ok=True)

        if not self.paths.pf_conf_path.exists():
            self.paths.pf_conf_path.parent.mkdir(parents=True, exist_ok=True)
            self.paths.pf_conf_path.write_text(
                'anchor "com.apple/*"\nload anchor "com.apple" from "/etc/pf.anchors/com.apple"\n'
            )

        if not self.paths.backup_pf_conf_path.exists():
            shutil.copy2(self.paths.pf_conf_path, self.paths.backup_pf_conf_path)

        pf_conf = ensure_pf_hook(self.paths.pf_conf_path.read_text())
        self.paths.pf_conf_path.write_text(pf_conf)
        default = default_config(interface)
        self.paths.anchor_path.write_text(render_anchor(default.interface, default.enabled, default.rules))

        if not self.paths.config_path.exists():
            save_config(self.paths.config_path, default_config(interface))

        self._save_state({"pf_enabled_by_macfw": False, "installed": True})

    def uninstall(self) -> None:
        state = self._load_state()
        if state.get("pf_enabled_by_macfw"):
            self._disable_pf()

        if self.paths.backup_pf_conf_path.exists():
            shutil.copy2(self.paths.backup_pf_conf_path, self.paths.pf_conf_path)
        elif self.paths.pf_conf_path.exists():
            self.paths.pf_conf_path.write_text(remove_pf_hook(self.paths.pf_conf_path.read_text()))

        if self.paths.anchor_path.exists():
            self.paths.anchor_path.unlink()

        if self.paths.config_path.exists():
            self.paths.config_path.unlink()
        if self.paths.state_path.exists():
            self.paths.state_path.unlink()

    def add_rule(self, rule: Rule) -> None:
        config = self._load_config()
        if rule not in config.rules:
            rules = sorted(config.rules + [rule], key=config_rule_sort_key)
            save_config(self.paths.config_path, Config(interface=config.interface, enabled=config.enabled, rules=rules))
            self._sync_anchor()

    def remove_rule(self, rule: Rule) -> None:
        config = self._load_config()
        rules = [item for item in config.rules if not rule_matches(rule, item)]
        save_config(self.paths.config_path, Config(interface=config.interface, enabled=config.enabled, rules=rules))
        self._sync_anchor()

    def find_matching_rules(self, rule: Rule, *, action: str | None) -> List[Rule]:
        config = self._load_config()
        matches: List[Rule] = []
        for candidate in config.rules:
            if action is not None and candidate.action != action:
                continue
            if action is None:
                if rule_shape_matches(rule, candidate):
                    matches.append(candidate)
                continue
            probe = Rule(action=action, source=rule.source, port=rule.port, proto=rule.proto, family=rule.family)
            if rule_matches(probe, candidate):
                matches.append(candidate)
        return matches

    def enable(self) -> None:
        config = self._load_config()
        save_config(self.paths.config_path, Config(interface=config.interface, enabled=True, rules=config.rules))
        self._sync_anchor()

        if not self._pf_is_enabled():
            self._run(["pfctl", "-f", str(self.paths.pf_conf_path)])
            self._run(["pfctl", "-e"])
            state = self._load_state()
            state["pf_enabled_by_macfw"] = True
            self._save_state(state)

    def disable(self) -> None:
        config = self._load_config()
        save_config(self.paths.config_path, Config(interface=config.interface, enabled=False, rules=config.rules))
        self._sync_anchor()

        state = self._load_state()
        if state.get("pf_enabled_by_macfw"):
            self._disable_pf()
            state["pf_enabled_by_macfw"] = False
            self._save_state(state)

    def status(self) -> Dict[str, object]:
        config = self._load_config()
        return {
            "installed": self.paths.config_path.exists(),
            "enabled": config.enabled,
            "interface": config.interface,
            "pf_enabled": self._pf_is_enabled(),
            "rules": [format_status_rule(rule) for rule in config.rules] + default_status_rules(config.interface) + ["deny from any to self port all proto any"],
        }

    def _sync_anchor(self) -> None:
        config = self._load_config()
        self.paths.anchor_path.parent.mkdir(parents=True, exist_ok=True)
        self.paths.anchor_path.write_text(render_anchor(config.interface, config.enabled, config.rules))
        self._validate_pf_conf()
        if self._pf_is_enabled():
            self._run(["pfctl", "-f", str(self.paths.pf_conf_path)])

    def _validate_pf_conf(self) -> None:
        if not self.live_system:
            return
        self._run(["pfctl", "-vnf", str(self.paths.pf_conf_path)])

    def _pf_is_enabled(self) -> Optional[bool]:
        if not self.live_system:
            state = self._load_state()
            return bool(state.get("pf_enabled_by_macfw", False) and self._load_config().enabled)
        try:
            result = self._run(["pfctl", "-s", "info"])
        except Exception:
            return None
        return "Status: Enabled" in result.stdout

    def _disable_pf(self) -> None:
        if self.live_system:
            self._run(["pfctl", "-d"])

    def _load_config(self) -> Config:
        if not self.paths.config_path.exists():
            raise FileNotFoundError("macfw is not installed")
        return load_config(self.paths.config_path)

    def _load_state(self) -> Dict[str, object]:
        if not self.paths.state_path.exists():
            return {}
        return json.loads(self.paths.state_path.read_text())

    def _save_state(self, payload: Dict[str, object]) -> None:
        self.paths.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.paths.state_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")

    def _run(self, command: List[str]) -> subprocess.CompletedProcess:
        return self.runner(command)


def format_status_rule(rule: Rule) -> str:
    line = f"{rule.action} from {rule.source} to self port {rule.port} proto {rule.proto}"
    if rule.family != "both":
        line += f" family {rule.family}"
    return line
