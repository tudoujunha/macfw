import unittest

from macfw.config import Rule
from macfw.pf import default_status_rules, ensure_pf_hook, remove_pf_hook, render_anchor


class PfRenderingTests(unittest.TestCase):
    def test_render_anchor_allows_loopback_and_lan_by_default(self) -> None:
        rendered = render_anchor("en1", True, [Rule(action="allow", source="any", port="22", proto="tcp", family="both")])

        self.assertIn("pass in quick on lo0 all keep state", rendered)
        self.assertIn("pass in quick on $ext_if from { ($ext_if:network), 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16, fe80::/10, fd00::/8 } to self keep state", rendered)
        self.assertIn("100.64.0.0/10", rendered)
        self.assertIn("block in log on $ext_if all", rendered)
        self.assertNotIn("lan_sources =", rendered)
        self.assertNotIn("local_sources =", rendered)

    def test_render_anchor_supports_any_lan_and_local_sources(self) -> None:
        rendered = render_anchor(
            "en1",
            True,
            [
                Rule(action="allow", source="any", port="22", proto="tcp", family="both"),
                Rule(action="allow", source="lan", port="3000", proto="tcp", family="both"),
                Rule(action="allow", source="local", port="5353", proto="udp", family="both"),
            ],
        )

        self.assertIn('pass in quick on $ext_if proto tcp from any to self port 22 keep state', rendered)
        self.assertIn('pass in quick on $ext_if proto tcp from { ($ext_if:network), 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16, fe80::/10, fd00::/8 } to self port 3000 keep state', rendered)
        self.assertIn('pass in quick on lo0 proto udp from any to { 127.0.0.1, ::1 } port 5353 keep state', rendered)

    def test_render_anchor_expands_any_proto_port_rule(self) -> None:
        rendered = render_anchor(
            "en1",
            True,
            [Rule(action="allow", source="any", port="443", proto="any", family="ipv4")],
        )

        self.assertIn("pass in quick on $ext_if inet proto tcp from any to self port 443 keep state", rendered)
        self.assertIn("pass in quick on $ext_if inet proto udp from any to self port 443 keep state", rendered)

    def test_render_anchor_places_deny_before_allow(self) -> None:
        rendered = render_anchor(
            "en1",
            True,
            [
                Rule(action="allow", source="any", port="22", proto="tcp", family="both"),
                Rule(action="deny", source="any", port="22", proto="tcp", family="ipv6"),
            ],
        )

        self.assertLess(
            rendered.index("block drop in quick on $ext_if inet6 proto tcp from any to self port 22"),
            rendered.index("pass in quick on $ext_if proto tcp from any to self port 22 keep state"),
        )

    def test_render_anchor_for_disabled_config_keeps_rules_closed(self) -> None:
        rendered = render_anchor("en1", False, [])

        self.assertIn("# macfw disabled", rendered)
        self.assertNotIn("port 22", rendered)

    def test_default_status_rules_include_tailscale_range(self) -> None:
        rules = default_status_rules("en1")

        self.assertIn("allow from 100.64.0.0/10 to self port all proto any family ipv4", rules)
        self.assertIn("allow from (en1:network) to self port all proto any", rules)

    def test_pf_hook_is_added_once_and_removed_cleanly(self) -> None:
        base = '\n'.join(
            [
                'anchor "com.apple/*"',
                'load anchor "com.apple" from "/etc/pf.anchors/com.apple"',
            ]
        )

        with_hook = ensure_pf_hook(base)
        self.assertEqual(with_hook.splitlines().count('anchor "macfw"'), 1)
        self.assertEqual(with_hook.splitlines().count('load anchor "macfw" from "/etc/pf.anchors/macfw"'), 1)

        round_trip = remove_pf_hook(with_hook)
        self.assertEqual(base, round_trip.strip())


if __name__ == "__main__":
    unittest.main()
