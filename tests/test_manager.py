import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess

from macfw.config import Rule
from macfw.manager import MacFwManager, Paths


class FakeRunner:
    def __init__(self) -> None:
        self.commands = []
        self.pf_enabled = False

    def __call__(self, command):
        self.commands.append(command)
        if command[:3] == ["pfctl", "-s", "info"]:
            status = "Enabled" if self.pf_enabled else "Disabled"
            return CompletedProcess(command, 0, stdout=f"Status: {status}\n", stderr="")
        if command[:2] == ["pfctl", "-e"]:
            self.pf_enabled = True
            return CompletedProcess(command, 0, stdout="pf enabled\n", stderr="")
        if command[:2] == ["pfctl", "-d"]:
            self.pf_enabled = False
            return CompletedProcess(command, 0, stdout="pf disabled\n", stderr="")
        return CompletedProcess(command, 0, stdout="", stderr="")


class ManagerTests(unittest.TestCase):
    def test_find_matching_rules_without_action_finds_single_deny_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()
            manager = MacFwManager(Paths(home=home, root=root), live_system=False)

            manager.install("en1")
            manager.add_rule(Rule(action="deny", source="any", port="22", proto="tcp", family="ipv6"))

            matches = manager.find_matching_rules(Rule(action="allow", source="any", port="22", proto="tcp", family="both"), action=None)

            self.assertEqual([Rule(action="deny", source="any", port="22", proto="tcp", family="ipv6")], matches)

    def test_find_matching_rules_without_action_can_be_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()
            manager = MacFwManager(Paths(home=home, root=root), live_system=False)

            manager.install("en1")
            manager.add_rule(Rule(action="allow", source="any", port="22", proto="tcp", family="ipv6"))
            manager.add_rule(Rule(action="deny", source="any", port="22", proto="tcp", family="ipv6"))

            matches = manager.find_matching_rules(Rule(action="allow", source="any", port="22", proto="tcp", family="both"), action=None)

            self.assertEqual(2, len(matches))

    def test_remove_rule_without_family_matches_specific_family_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()
            manager = MacFwManager(Paths(home=home, root=root), live_system=False)

            manager.install("en1")
            manager.add_rule(Rule(action="allow", source="any", port="22", proto="tcp", family="ipv6"))
            manager.remove_rule(Rule(action="allow", source="any", port="22", proto="tcp", family="both"))

            self.assertEqual([], manager._load_config().rules)

    def test_remove_rule_with_explicit_family_is_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()
            manager = MacFwManager(Paths(home=home, root=root), live_system=False)

            manager.install("en1")
            manager.add_rule(Rule(action="allow", source="any", port="22", proto="tcp", family="both"))
            manager.remove_rule(Rule(action="allow", source="any", port="22", proto="tcp", family="ipv6"))

            self.assertEqual([Rule(action="allow", source="any", port="22", proto="tcp", family="both")], manager._load_config().rules)

    def test_enable_loads_pf_conf_before_enabling_when_pf_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()
            runner = FakeRunner()
            manager = MacFwManager(
                Paths(home=home, root=root),
                runner=runner,
                live_system=True,
            )

            manager.install("en1")
            manager.add_rule(Rule(action="allow", source="any", port="22", proto="tcp", family="both"))
            manager.enable()

            commands = [" ".join(cmd) for cmd in runner.commands]
            load_index = commands.index(f"pfctl -f {root / 'etc' / 'pf.conf'}")
            enable_index = commands.index("pfctl -e")

            self.assertLess(load_index, enable_index)


if __name__ == "__main__":
    unittest.main()
