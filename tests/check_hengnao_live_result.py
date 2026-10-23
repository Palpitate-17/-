"""Contract checks for the HengNao live result code node."""

import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
import unittest
from types import SimpleNamespace


source = Path(__file__).resolve().parents[1] / "prototype" / "hengnao_live_result_node.py"
spec = importlib.util.spec_from_file_location("hengnao_live_result_node", source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LiveResultChecks(unittest.TestCase):
    def setUp(self):
        self.plan = {"route": "scan", "target_url": module.TARGET}
        self.result = {"scan_id": datetime.now(timezone.utc).isoformat(), "target_url": module.TARGET,
                       "data_kind": "public_scanner_testbed", "execution_mode": "on_demand",
                       "scan_status": "complete", "pages": [{"url": module.TARGET, "status": 200}],
                       "findings": [], "tool_checks": [{"observations": []}], "errors": []}

    def test_valid_fresh_result(self):
        output = module.inspect(json.dumps(self.plan), json.dumps({"result_key": json.dumps(self.result)}))
        self.assertEqual(output["status"], "live_result")
        self.assertIn("本轮实时请求", output["report"])

    def test_handler_returns_readable_end_node_value(self):
        args = SimpleNamespace(input=SimpleNamespace(input=json.dumps(self.plan), scan_result=json.dumps(self.result)))
        self.assertTrue(module.handler(args)["result_key"].startswith("公开测试靶场即时巡检"))

    def test_other_target_rejected(self):
        self.plan["target_url"] = "https://example.com/"
        self.assertEqual(module.inspect(self.plan, self.result)["status"], "out_of_scope")

    def test_partial_result_is_not_clean(self):
        self.result["scan_status"] = "partial"
        self.result["errors"] = [{"url": module.TARGET + "mixedcontent/index.html", "error": "request_failed"}]
        output = module.inspect(self.plan, self.result)
        self.assertEqual(output["status"], "partial_result")
        self.assertIn("不能据此判断无发现", output["report"])

    def test_outside_evidence_rejected(self):
        self.result["findings"] = [{"url": "https://example.com/", "category": "other"}]
        self.assertEqual(module.inspect(self.plan, self.result)["status"], "invalid_result")


if __name__ == "__main__":
    unittest.main()
