import unittest

from prototype.hengnao_route_node import route_plan


TARGET = "https://public-firing-range.appspot.com/"


class RouteNodeTests(unittest.TestCase):
    def test_preapproved_target_is_routed(self):
        message = f"请巡检 {TARGET}"
        plan = {"next_action": "call_scan", "target_candidate": TARGET,
                "requested_checks": ["weak_config"]}
        result = route_plan(plan, message)
        self.assertEqual(result["route"], "scan")
        self.assertEqual(result["target_url"], TARGET)

    def test_unlisted_public_target_is_refused(self):
        candidate = "https://example.com/"
        plan = {"next_action": "call_scan", "target_candidate": candidate,
                "requested_checks": ["weak_config"]}
        result = route_plan(plan, f"请巡检 {candidate}")
        self.assertEqual(result["route"], "refuse")
        self.assertEqual(result["target_url"], "")

    def test_blacklisted_and_nonpublic_targets_are_refused(self):
        for candidate in ("https://www.gov.cn/", "http://127.0.0.1/", "https://intranet.local/"):
            plan = {"next_action": "call_scan", "target_candidate": candidate,
                    "requested_checks": ["weak_config"]}
            with self.subTest(candidate=candidate):
                self.assertEqual(route_plan(plan, f"请巡检 {candidate}")["route"], "refuse")

    def test_model_cannot_supply_unmentioned_target(self):
        plan = {"next_action": "call_scan", "target_candidate": TARGET,
                "requested_checks": ["weak_config"]}
        self.assertEqual(route_plan(plan, "请巡检网站")["route"], "ask_user")


if __name__ == "__main__":
    unittest.main()
