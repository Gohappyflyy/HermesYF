import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / 'skills/security/hermesyf-authorized-assessment/SKILL.md'
REFERENCE = SKILL.parent / 'references/public-scan.md'

class PublicScanSkillTests(unittest.TestCase):
    def test_reference_is_linked(self):
        self.assertIn('references/public-scan.md', SKILL.read_text())
        self.assertTrue(REFERENCE.is_file())

    def test_workflow_contract(self):
        text = REFERENCE.read_text()
        for heading in ['授权资产清单', '服务识别', '模板审核', '停止条件', '误报复核', '证据报告']:
            with self.subTest(heading=heading):
                self.assertIn(heading, text)

    def test_no_tool_execution_claim(self):
        self.assertIn('不是扫描执行器', REFERENCE.read_text())
