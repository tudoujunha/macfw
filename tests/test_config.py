import json
import tempfile
import unittest
from pathlib import Path

from macfw.config import Config, Rule, load_config, save_config


class ConfigTests(unittest.TestCase):
    def test_save_and_load_config_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            config = Config(
                interface="en1",
                enabled=True,
                rules=[
                    Rule(action="allow", source="any", port="22", proto="tcp", family="both"),
                    Rule(action="allow", source="100.64.0.0/10", port="all", proto="any", family="ipv4"),
                ],
            )

            save_config(path, config)
            loaded = load_config(path)

            self.assertEqual(config, loaded)

    def test_save_config_is_human_readable_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            save_config(path, Config(interface="en1", enabled=False, rules=[]))

            payload = json.loads(path.read_text())

            self.assertEqual(2, payload["schema_version"])
            self.assertEqual("en1", payload["interface"])
            self.assertFalse(payload["enabled"])
            self.assertEqual([], payload["rules"])

    def test_load_config_migrates_legacy_scope_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "interface": "en1",
                        "enabled": True,
                        "rules": [
                            {"port": 22, "proto": "tcp", "scope": "public"},
                            {"port": 5353, "proto": "udp", "scope": "lan"},
                            {"port": 8080, "proto": "tcp", "scope": "local-only"},
                        ],
                    }
                )
            )

            config = load_config(path)

            self.assertEqual(
                [
                    Rule(action="allow", source="any", port="22", proto="tcp", family="both"),
                    Rule(action="allow", source="lan", port="5353", proto="udp", family="both"),
                    Rule(action="allow", source="local", port="8080", proto="tcp", family="both"),
                ],
                config.rules,
            )

    def test_rule_validation_rejects_bad_proto(self) -> None:
        with self.assertRaises(ValueError):
            Rule(action="allow", source="any", port="22", proto="bogus", family="both")

    def test_rule_validation_infers_family_from_source(self) -> None:
        rule = Rule(action="allow", source="192.168.0.0/16", port="all", proto="any", family="both")

        self.assertEqual("ipv4", rule.family)
        self.assertEqual("192.168.0.0/16", rule.source)


if __name__ == "__main__":
    unittest.main()
