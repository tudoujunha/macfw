import io
import json
import tempfile
import unittest
from pathlib import Path

from macfw.cli import main, ssh_session_warning


class CliTests(unittest.TestCase):
    def test_version_is_reported(self) -> None:
        stdout = io.StringIO()
        exit_code = main(["--version"], stdout=stdout)

        self.assertEqual(0, exit_code)
        self.assertIn("macfw 0.1.0", stdout.getvalue())

    def test_deny_help_shows_ufw_like_examples(self) -> None:
        stdout = io.StringIO()
        exit_code = main(["deny", "--help"], stdout=stdout)

        self.assertEqual(0, exit_code)
        self.assertIn("22/tcp", stdout.getvalue())
        self.assertIn("from any to any port 22 proto tcp", stdout.getvalue())

    def test_allow_help_shows_ufw_like_examples(self) -> None:
        stdout = io.StringIO()
        exit_code = main(["allow", "--help"], stdout=stdout)

        self.assertEqual(0, exit_code)
        self.assertIn("22/tcp", stdout.getvalue())
        self.assertIn("from any to any port 22 proto tcp", stdout.getvalue())

    def test_allow_add_defaults_to_tcp_both(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["allow", "add", "23"], home=home, root=root, stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            self.assertIn("added from any to self port 23 proto tcp", stdout.getvalue())

    def test_allow_ipv6_shorthand_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["allow", "22/tcp", "ipv6"], home=home, root=root, stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            self.assertIn("family ipv6", stdout.getvalue())

    def test_allow_shorthand_supports_specific_ipv4_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["allow", "22/tcp", "from", "1.2.3.4"], home=home, root=root, stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            self.assertIn("added from 1.2.3.4/32 to self port 22 proto tcp family ipv4", stdout.getvalue())

    def test_allow_shorthand_supports_specific_ipv6_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["allow", "22/tcp", "from", "2001:db8::1"], home=home, root=root, stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            self.assertIn("added from 2001:db8::1/128 to self port 22 proto tcp family ipv6", stdout.getvalue())

    def test_allow_shorthand_supports_any_ipv6_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["allow", "22/tcp", "from", "any", "ipv6"], home=home, root=root, stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            self.assertIn("added from any to self port 22 proto tcp family ipv6", stdout.getvalue())

    def test_deny_ipv6_rule_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["deny", "22/tcp", "ipv6"], home=home, root=root, stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            self.assertIn("added from any to self port 22 proto tcp family ipv6", stdout.getvalue())

            config = json.loads((home / ".config" / "macfw" / "config.json").read_text())
            self.assertEqual("deny", config["rules"][0]["action"])

    def test_delete_without_family_removes_more_specific_allow_family(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))
            self.assertEqual(0, main(["allow", "22/tcp", "ipv6"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["delete", "22/tcp"], home=home, root=root, stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            config = json.loads((home / ".config" / "macfw" / "config.json").read_text())
            self.assertEqual([], config["rules"])

    def test_delete_with_explicit_family_does_not_remove_broader_allow_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))
            self.assertEqual(0, main(["allow", "22/tcp"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["delete", "22/tcp", "ipv6"], home=home, root=root, stdout=stdout)

            self.assertEqual(2, exit_code, stdout.getvalue())
            self.assertIn("no matching rule found", stdout.getvalue())
            config = json.loads((home / ".config" / "macfw" / "config.json").read_text())
            self.assertEqual(1, len(config["rules"]))
            self.assertEqual("both", config["rules"][0]["family"])

    def test_delete_deny_without_family_removes_more_specific_deny_family(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))
            self.assertEqual(0, main(["deny", "22/tcp", "ipv6"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["delete", "deny", "22/tcp"], home=home, root=root, stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            config = json.loads((home / ".config" / "macfw" / "config.json").read_text())
            self.assertEqual([], config["rules"])

    def test_delete_without_action_removes_single_matching_deny_rule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))
            self.assertEqual(0, main(["deny", "22/tcp", "ipv6"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["delete", "22/tcp"], home=home, root=root, stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            config = json.loads((home / ".config" / "macfw" / "config.json").read_text())
            self.assertEqual([], config["rules"])

    def test_delete_without_action_reports_ambiguous_when_allow_and_deny_both_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))
            self.assertEqual(0, main(["allow", "22/tcp", "ipv6"], home=home, root=root, stdout=io.StringIO()))
            self.assertEqual(0, main(["deny", "22/tcp", "ipv6"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["delete", "22/tcp"], home=home, root=root, stdout=stdout)

            self.assertEqual(2, exit_code, stdout.getvalue())
            self.assertIn("ambiguous delete", stdout.getvalue())
            self.assertIn("delete allow 22/tcp", stdout.getvalue())
            self.assertIn("delete deny 22/tcp", stdout.getvalue())

    def test_allow_from_source_rule_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(
                ["allow", "from", "192.168.0.0/16"],
                home=home,
                root=root,
                stdout=stdout,
            )

            self.assertEqual(0, exit_code, stdout.getvalue())
            self.assertIn("added from 192.168.0.0/16 to self port all proto any family ipv4", stdout.getvalue())

    def test_parse_error_suggests_sudo_for_mutating_command(self) -> None:
        stdout = io.StringIO()
        exit_code = main(
            ["allow"],
            root=Path("/"),
            stdout=stdout,
            geteuid=lambda: 501,
        )

        self.assertEqual(2, exit_code)
        self.assertIn("hint: macfw allow usually requires sudo", stdout.getvalue())
        self.assertIn("usage:", stdout.getvalue())

    def test_allow_requires_sudo_and_shows_exact_retry_command(self) -> None:
        stdout = io.StringIO()
        exit_code = main(
            ["allow", "23"],
            root=Path("/"),
            stdout=stdout,
            geteuid=lambda: 501,
        )

        self.assertEqual(1, exit_code)
        self.assertIn("error: macfw allow requires sudo", stdout.getvalue())
        self.assertIn("hint: try: sudo macfw allow 23", stdout.getvalue())

    def test_allow_and_status_show_expanded_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))
            self.assertEqual(0, main(["allow", "22/tcp"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["status"], home=home, root=root, stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            self.assertIn("To", stdout.getvalue())
            self.assertIn("Action", stdout.getvalue())
            self.assertIn("From", stdout.getvalue())
            self.assertIn("Anywhere", stdout.getvalue())
            self.assertIn("Anywhere (v6)", stdout.getvalue())
            self.assertIn("22/tcp", stdout.getvalue())
            self.assertIn("DENY IN", stdout.getvalue())
            self.assertLess(stdout.getvalue().index("22/tcp"), stdout.getvalue().index("127.0.0.1/32"))

            config = json.loads((home / ".config" / "macfw" / "config.json").read_text())
            self.assertEqual(
                [
                    {
                        "action": "allow",
                        "family": "both",
                        "port": "22",
                        "proto": "tcp",
                        "source": "any",
                    }
                ],
                config["rules"],
            )

    def test_status_explains_unknown_pf_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))

            stdout = io.StringIO()
            exit_code = main(["status"], home=home, root=Path("/"), stdout=stdout)

            self.assertEqual(0, exit_code, stdout.getvalue())
            self.assertIn("pf: unknown (run with sudo macfw status to verify live pf state)", stdout.getvalue())

    def test_uninstall_restores_pf_conf_and_removes_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            pf_conf = root / "etc" / "pf.conf"
            anchor = root / "etc" / "pf.anchors" / "macfw"
            pf_conf.parent.mkdir(parents=True)
            anchor.parent.mkdir(parents=True)
            home.mkdir()
            pf_conf.write_text('anchor "com.apple/*"\nload anchor "com.apple" from "/etc/pf.anchors/com.apple"\n')

            self.assertEqual(0, main(["install", "--interface", "en1"], home=home, root=root, stdout=io.StringIO()))
            self.assertTrue(anchor.exists())
            self.assertIn('anchor "macfw"', pf_conf.read_text())

            self.assertEqual(0, main(["uninstall"], home=home, root=root, stdout=io.StringIO()))
            self.assertFalse(anchor.exists())
            self.assertNotIn('anchor "macfw"', pf_conf.read_text())

    def test_status_reports_not_installed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            root = Path(tmp) / "root"
            home.mkdir()
            root.mkdir()

            stdout = io.StringIO()
            exit_code = main(["status"], home=home, root=root, stdout=stdout)

            self.assertEqual(1, exit_code)
            self.assertIn("macfw is not installed", stdout.getvalue())

    def test_disable_requires_sudo_on_live_system(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()

            stdout = io.StringIO()
            exit_code = main(
                ["disable"],
                home=home,
                root=Path("/"),
                stdout=stdout,
                geteuid=lambda: 501,
            )

            self.assertEqual(1, exit_code)
            self.assertIn("error: macfw disable requires sudo", stdout.getvalue())
            self.assertIn("hint: try: sudo macfw disable", stdout.getvalue())

    def test_ssh_session_warning_mentions_disconnect_risk(self) -> None:
        warning = ssh_session_warning({"SSH_CONNECTION": "1 2 3 4"}, "enable")

        self.assertIn("SSH session", warning)
        self.assertIn("may interrupt existing SSH connections", warning)


if __name__ == "__main__":
    unittest.main()
