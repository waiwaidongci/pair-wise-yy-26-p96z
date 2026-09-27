import os, sys, tempfile, unittest
from datetime import date, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import DomainError, PublicIdConflict, VulnerabilityDB


def day(offset):
    return (date.today() + timedelta(days=offset)).isoformat()


class PublicIdLedgerTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db"); os.close(fd)
        self.db = VulnerabilityDB(self.path)
        self.reporter = self.db.add_user("报告人", "reporter", "研究所")
        self.coord = self.db.add_user("协调员", "coordinator", "响应中心")
        self.coord2 = self.db.add_user("协调员乙", "coordinator", "另一中心")
        self.maint = self.db.add_user("维护者", "maintainer", "项目组")
        self.product = self.db.add_product("网关", "项目组")
        self.product2 = self.db.add_product("负载均衡", "项目组")
        self.report = self.db.create_report(
            "鉴权绕过", self.product, self.reporter, "特制请求可绕过鉴权", day(40), ["3.2.0"])
        self.report2 = self.db.create_report(
            "信息泄露", self.product2, self.reporter, "错误页泄露堆栈", day(50), ["1.0.0"])
        self.product3 = self.db.add_product("缓存服务", "项目组")
        self.report3 = self.db.create_report(
            "缓存投毒", self.product3, self.reporter, "缓存键可被污染", day(5), ["2.1.0"])

    def tearDown(self):
        self.db.close(); os.unlink(self.path)

    def _advance_to_resolved(self, report=None):
        report = self.report if report is None else report
        self.db.add_member(report, self.maint, "maintainer", self.coord)
        self.db.set_status(report, "triaged", self.coord)
        self.db.set_status(report, "fixing", self.coord)
        self.db.set_fix_plan(report, self.maint, "增加鉴权前置校验", day(20))
        self.db.set_status(report, "resolved", self.coord)
        self.db.create_advisory_draft(report, "受影响版本需要尽快升级到修复版本。", self.coord)

    def test_register_and_duplicate_returns_existing_report(self):
        reg = self.db.register_public_id(
            "cve-2026-10001", self.report, day(10),
            "https://example.org/adv/CVE-2026-10001", self.coord)
        self.assertEqual("CVE-2026-10001", reg["identifier"])
        self.assertEqual("reserved", reg["status"])
        self.assertEqual(self.report, reg["report_id"])
        # 同一份报告重复登记：幂等返回已有登记
        again = self.db.register_public_id(
            "CVE-2026-10001", self.report, day(20),
            "https://example.org/other", self.coord)
        self.assertEqual(reg["id"], again["id"])
        self.assertEqual(day(10), again["reserved_until"])
        self.assertNotIn("conflict", [e["action"] for e in self.db.public_id_ledger()["events"]])
        # 另一份报告抢注同一编号：返回持有报告
        with self.assertRaises(PublicIdConflict) as ctx:
            self.db.register_public_id(
                "CVE-2026-10001", self.report2, day(10),
                "https://example.org/x", self.coord2)
        self.assertEqual(self.report, ctx.exception.holder["report_id"])
        ledger = self.db.public_id_ledger()
        self.assertEqual(1, len(ledger["conflicts"]))
        self.assertEqual(self.report2, ledger["conflicts"][0]["attempt_report"]["id"])
        self.assertEqual(self.report, ledger["conflicts"][0]["holder"]["report_id"])

    def test_register_requires_coordinator_and_valid_fields(self):
        with self.assertRaisesRegex(DomainError, "协调员"):
            self.db.register_public_id("CVE-2026-20002", self.report, day(10),
                                       "https://example.org/x", self.reporter)
        with self.assertRaisesRegex(DomainError, "公开编号"):
            self.db.register_public_id("a/b", self.report, day(10),
                                       "https://example.org/x", self.coord)
        with self.assertRaisesRegex(DomainError, "预留到期日"):
            self.db.register_public_id("CVE-2026-20002", self.report, "not-a-date",
                                       "https://example.org/x", self.coord)
        with self.assertRaisesRegex(DomainError, "公告地址"):
            self.db.register_public_id("CVE-2026-20002", self.report, day(10),
                                       "ftp://example.org/x", self.coord)

    def test_withdraw_releases_identifier(self):
        reg = self.db.register_public_id(
            "CVE-2026-30003", self.report, day(10),
            "https://example.org/a", self.coord)
        self.db.withdraw_public_id(reg["id"], self.coord, "编号规划调整")
        reg2 = self.db.register_public_id(
            "CVE-2026-30003", self.report2, day(12),
            "https://example.org/b", self.coord)
        self.assertEqual(self.report2, reg2["report_id"])
        self.assertEqual("reserved", reg2["status"])
        actions = [e["action"] for e in self.db.public_id_ledger()["events"]]
        self.assertIn("withdraw", actions)
        # 已撤回的登记不能再续期
        with self.assertRaisesRegex(DomainError, "撤回"):
            self.db.renew_public_id(reg["id"], day(30), self.coord, "需要继续预留")
        # 非协调员不能撤回
        with self.assertRaisesRegex(DomainError, "协调员"):
            self.db.withdraw_public_id(reg2["id"], self.reporter)

    def test_renew_keeps_old_and_new_deadlines(self):
        reg = self.db.register_public_id(
            "CVE-2026-40004", self.report, day(10),
            "https://example.org/a", self.coord)
        renewed = self.db.renew_public_id(reg["id"], day(30), self.coord,
                                          "修复还在验证，需要延长预留",
                                          "https://example.org/a2")
        self.assertEqual(day(30), renewed["reserved_until"])
        self.assertEqual("renewed", renewed["status"])
        ledger = self.db.public_id_ledger()
        event = next(e for e in ledger["events"] if e["action"] == "renew")
        self.assertEqual(day(10), event["old_deadline"])
        self.assertEqual(day(30), event["new_deadline"])
        self.assertEqual("https://example.org/a2", event["advisory_url"])
        with self.assertRaisesRegex(DomainError, "理由"):
            self.db.renew_public_id(reg["id"], day(40), self.coord, "短")
        with self.assertRaisesRegex(DomainError, "晚于"):
            self.db.renew_public_id(reg["id"], day(20), self.coord, "更早的截止日期不行")

    def test_expired_reservation_blocks_publish_and_renew_unblocks(self):
        self._advance_to_resolved(self.report3)
        reg = self.db.register_public_id(
            "CVE-2026-50005", self.report3, day(5),
            "https://example.org/a", self.coord)
        # 预留到期（披露日晚于预留到期日）不能披露
        with self.assertRaisesRegex(DomainError, "到期"):
            self.db.publish_report(self.report3, self.coord, day(6))
        block_events = [e for e in self.db.public_id_ledger()["events"]
                        if e["action"] == "publish_block"]
        self.assertEqual(1, len(block_events))
        # 续期后可披露
        self.db.renew_public_id(reg["id"], day(60), self.coord, "修复验证需要更多时间")
        self.db.publish_report(self.report3, self.coord, day(45))
        # 已公开的报告不能再次披露，也不能再登记编号
        with self.assertRaisesRegex(DomainError, "再次披露"):
            self.db.publish_report(self.report3, self.coord, day(46))
        with self.assertRaisesRegex(DomainError, "已公开"):
            self.db.register_public_id("CVE-2026-50006", self.report3, day(60),
                                       "https://example.org/b", self.coord)

    def test_ledger_shows_expiring_within_window(self):
        self.db.register_public_id(
            "CVE-2026-60006", self.report, day(3),
            "https://example.org/a", self.coord)
        self.db.register_public_id(
            "CVE-2026-60007", self.report2, day(30),
            "https://example.org/b", self.coord)
        soon = self.db.public_id_ledger(within_days=7)["expiring"]
        self.assertEqual(["CVE-2026-60006"], [r["identifier"] for r in soon])
        wider = self.db.public_id_ledger(within_days=45)["expiring"]
        self.assertEqual(2, len(wider))
        # 撤回后不再出现在即将到期中
        reg_id = self.db.public_id_ledger()["registrations"][-1]["id"]
        self.db.withdraw_public_id(reg_id, self.coord, "释放编号")
        self.assertEqual([], self.db.public_id_ledger(within_days=7)["expiring"])

    def test_report_payload_includes_active_registration(self):
        self.db.register_public_id(
            "CVE-2026-70007", self.report, day(10),
            "https://example.org/a", self.coord)
        payload = self.db.get_report_for_user(self.report, self.coord)
        self.assertEqual("CVE-2026-70007", payload["public_id_registration"]["identifier"])


if __name__ == "__main__":
    unittest.main()
