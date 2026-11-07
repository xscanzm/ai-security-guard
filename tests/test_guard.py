# -*- coding: utf-8 -*-
"""ai-security-guard 的回归测试。

运行：
    python -m unittest discover -s tests -v
"""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS = os.path.join(ROOT, "scripts")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import engine
import guard
import rules


DEMO = os.path.join(ROOT, "examples", "vulnerable-demo")


class RuleLibraryTests(unittest.TestCase):
    def test_ids_are_unique_and_well_formed(self):
        ids = [r["id"] for r in rules.RULES] + list(rules.SPECIAL.keys())
        self.assertEqual(len(ids), len(set(ids)))
        for rid in ids:
            self.assertRegex(rid, r"^[CSPD]\d{3}[abc]?$")

    def test_severities_are_known(self):
        for rule in rules.RULES:
            self.assertIn(rule["severity"], rules.SEV_WEIGHT)
        for meta in rules.SPECIAL.values():
            self.assertIn(meta["severity"], rules.SEV_WEIGHT)

    def test_every_rule_has_why_and_fix(self):
        for rule in rules.RULES:
            self.assertTrue(rule["why"])
            self.assertGreaterEqual(len(rule["fix"]), 1)
        for meta in rules.SPECIAL.values():
            self.assertTrue(meta["why"])
            self.assertGreaterEqual(len(meta["fix"]), 1)

    def test_four_domains_covered(self):
        domains = {r["domain"] for r in rules.RULES}
        domains |= {m["domain"] for m in rules.SPECIAL.values()}
        self.assertEqual(domains, {"code", "skill", "doc", "perm"})


class MaskTests(unittest.TestCase):
    def test_secret_is_masked(self):
        raw = "sk-abcdefghijklmnopqrstuvwxyz012345"
        masked = engine.mask_secret(raw)
        self.assertNotIn(raw, masked)
        self.assertIn("****", masked)

    def test_phone_is_masked(self):
        self.assertEqual(engine.mask_phone("13812345678"), "138****5678")

    def test_id_is_masked(self):
        masked = engine.mask_id("110101199003071233")
        self.assertEqual(masked, "110101********1233")

    def test_email_is_masked(self):
        self.assertEqual(engine.mask_email("wang@example.com"), "w***@example.com")

    def test_none_keeps_code_readable(self):
        self.assertEqual(engine.mask_value("PythonREPLTool", "none"), "PythonREPLTool")


class ChecksumTests(unittest.TestCase):
    def test_valid_id(self):
        self.assertTrue(engine.id_checksum_ok("110101199003071233"))

    def test_invalid_id(self):
        self.assertFalse(engine.id_checksum_ok("110101199003071234"))

    def test_luhn(self):
        self.assertTrue(engine.luhn_ok("4111111111111111"))
        self.assertFalse(engine.luhn_ok("4111111111111112"))


class MatchTests(unittest.TestCase):
    def test_globs(self):
        self.assertTrue(engine.glob_match("app.py", rules.G_CODE))
        self.assertTrue(engine.glob_match(".env", rules.G_CONFIG))
        self.assertTrue(engine.glob_match(".env.local", rules.G_CONFIG))
        self.assertTrue(engine.glob_match("docs/a.md", rules.G_DOC))
        self.assertTrue(engine.glob_match(".claude/skills/x/SKILL.md", rules.G_SKILL))
        self.assertFalse(engine.glob_match("app.py", rules.G_DOC))


class DemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.findings = engine.scan_project(DEMO)
        cls.ids = {f["id"] for f in cls.findings}

    def test_demo_covers_all_four_domains(self):
        domains = {f["domain"] for f in self.findings}
        self.assertEqual(domains, {"code", "skill", "doc", "perm"})

    def test_demo_expected_findings(self):
        expected = {
            "C001", "C002", "C003", "C101", "C102", "C103", "C104a", "C105",
            "C106", "C107", "C108", "C109", "C110", "C111", "C112", "C114",
            "S001", "S002", "S003", "S004", "S005", "S008", "S009", "S013",
            "D001", "D002", "D004", "D005", "D006", "D008", "D010", "D011",
            "P001", "P002", "P003", "P004", "P005", "P006",
        }
        self.assertTrue(expected.issubset(self.ids), sorted(expected - self.ids))

    def test_demo_does_not_leak_raw_values(self):
        blob = json.dumps(self.findings, ensure_ascii=False)
        for raw in ("sk-demo000000000000000000000000000000",
                    "SuperSecret123", "Passw0rd123",
                    "13812345678", "110101199003071233",
                    "wangjianguo@quanjude-real.com"):
            self.assertNotIn(raw, blob)

    def test_demo_score_is_failing(self):
        value, grade, counts = engine.score(self.findings)
        self.assertEqual(value, 0)
        self.assertEqual(grade, "F")
        self.assertGreaterEqual(counts["critical"], 8)

    def test_demo_has_actionable_fixes(self):
        for f in self.findings:
            self.assertTrue(f["why"])
            self.assertGreaterEqual(len(f["fix"]), 1)
            self.assertNotIn("\n", f["snippet"])


class ProjectTests(unittest.TestCase):
    def test_clean_project_has_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "hello.py"), "w", encoding="utf-8") as f:
                f.write("print('hello')\n")
            self.assertEqual(engine.scan_project(tmp), [])

    def test_ai_guardignore_skips_demo_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "examples"))
            with open(os.path.join(tmp, "examples", "bad.py"), "w", encoding="utf-8") as f:
                f.write("eval(user_input)\n")
            with open(os.path.join(tmp, ".ai-guardignore"), "w", encoding="utf-8") as f:
                f.write("examples/\n")
            self.assertEqual(engine.scan_project(tmp), [])

    def test_custom_terms_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".ai-guard"))
            with open(os.path.join(tmp, ".ai-guard", "terms.txt"), "w", encoding="utf-8") as f:
                f.write("某某科技有限公司\n")
            with open(os.path.join(tmp, "case.md"), "w", encoding="utf-8") as f:
                f.write("客户：某某科技有限公司\n")
            ids = {f["id"] for f in engine.scan_project(tmp)}
            self.assertIn("D009", ids)

    def test_settings_file(self):
        findings = engine.scan_file(
            os.path.join(DEMO, ".claude", "settings.json"), DEMO)
        ids = {f["id"] for f in findings}
        self.assertTrue({"P001", "P002", "P003", "P004"}.issubset(ids))

    def test_mcp_file(self):
        findings = engine.scan_file(os.path.join(DEMO, ".mcp.json"), DEMO)
        ids = {f["id"] for f in findings}
        self.assertTrue({"P005", "P006"}.issubset(ids))

    def test_skill_file(self):
        findings = engine.scan_file(
            os.path.join(DEMO, ".claude", "skills", "meeting-helper", "SKILL.md"), DEMO)
        ids = {f["id"] for f in findings}
        self.assertTrue({"S001", "S009"}.issubset(ids))


class RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = engine.summary(DEMO, engine.scan_project(DEMO))

    def test_text_report_has_score_and_fix(self):
        text = guard.render_text(self.data)
        self.assertIn("安全分", text)
        self.assertIn("怎么改", text)

    def test_markdown_report(self):
        md = guard.render_md(self.data)
        self.assertIn("# AI 项目安全体检报告", md)
        self.assertIn("| 级别 | 编号 |", md)

    def test_json_report_round_trips(self):
        data = json.loads(guard.render_json(self.data))
        self.assertEqual(data["score"], self.data["score"])
        self.assertIn("findings", data)

    def test_should_fail_threshold(self):
        findings = [{"severity": "high"}]
        self.assertTrue(guard._should_fail(findings, "high"))
        self.assertFalse(guard._should_fail(findings, "critical"))
        self.assertFalse(guard._should_fail(findings, "none"))
        self.assertFalse(guard._should_fail([{"severity": "low"}], "high"))


if __name__ == "__main__":
    unittest.main()
