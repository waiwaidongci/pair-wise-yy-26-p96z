import os, sys, tempfile, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import DomainError, VulnerabilityDB

class VulnerabilityFlowTest(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix=".db"); os.close(fd); self.db=VulnerabilityDB(self.path)
        self.reporter=self.db.add_user("报告人","reporter","研究所"); self.coord=self.db.add_user("协调员","coordinator","响应中心"); self.maint=self.db.add_user("维护者","maintainer","项目组"); self.outsider=self.db.add_user("旁观者","reporter","外部")
        self.product=self.db.add_product("网关","项目组")
        self.report=self.db.create_report("鉴权绕过",self.product,self.reporter,"特制请求可绕过鉴权","2026-10-30",["3.2.0"])
    def tearDown(self): self.db.close(); os.unlink(self.path)
    def _advance_to_resolved(self):
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.set_status(self.report,"triaged",self.coord)
        self.db.set_status(self.report,"fixing",self.coord)
        self.db.set_fix_plan(self.report,self.maint,"增加鉴权前置校验", "2026-10-20")
        self.db.set_status(self.report,"resolved",self.coord)
        self.db.create_advisory_draft(self.report,"受影响版本 3.2.0。请升级到 3.2.1。",self.coord)
    def test_full_disclosure_flow_and_early_publish_rejected(self):
        self._advance_to_resolved()
        with self.assertRaisesRegex(DomainError,"提前披露"):
            self.db.publish_report(self.report,self.coord,"2026-10-01")
        self.db.publish_report(self.report,self.coord,"2026-10-30")
        advisory=self.db.get_advisory(self.report,self.outsider)
        self.assertEqual("published",advisory["status"])
        self.assertTrue(self.db.notifications_for(self.maint))
    def test_denies_outsider_and_duplicate_report(self):
        with self.assertRaisesRegex(DomainError,"无权"):
            self.db.get_report_for_user(self.report,self.outsider)
        with self.assertRaisesRegex(DomainError,"重复"):
            self.db.create_report("重复问题",self.product,self.reporter,"相同版本的另一份报告","2026-11-01",["3.2.0"])
        self.db.add_member(self.report,self.maint,"maintainer",self.coord)
        self.db.add_evidence(self.report,"协调材料","secret","coordinator",self.coord)
        visible=self.db.get_report_for_user(self.report,self.maint)
        self.assertEqual([],visible["evidence"])

class IdentifierRegistryTest(unittest.TestCase):
    def setUp(self):
        fd,self.path=tempfile.mkstemp(suffix=".db"); os.close(fd); self.db=VulnerabilityDB(self.path)
        self.reporter=self.db.add_user("报告人","reporter","研究所"); self.coord=self.db.add_user("协调员","coordinator","响应中心"); self.maint=self.db.add_user("维护者","maintainer","项目组")
        self.product=self.db.add_product("网关","项目组")
        self.report=self.db.create_report("鉴权绕过",self.product,self.reporter,"特制请求可绕过鉴权","2026-10-30",["3.2.0"])
        self.report2=self.db.create_report("日志泄露",self.product,self.reporter,"日志包含敏感信息","2026-11-15",["3.2.1"])
    def tearDown(self): self.db.close(); os.unlink(self.path)
    def test_duplicate_registration_returns_existing_and_logs_conflict(self):
        reg=self.db.register_identifier(self.report,"cve-2026-0001","2026-10-01","https://example.com/a1",self.coord,as_of="2026-09-01")
        self.assertFalse(reg["duplicate"]); self.assertEqual("CVE-2026-0001",reg["identifier"]); self.assertEqual("reserved",reg["status"])
        same=self.db.register_identifier(self.report,"CVE-2026-0001","2026-10-20","https://example.com/a1",self.coord,as_of="2026-09-02")
        self.assertTrue(same["duplicate"]); self.assertEqual(self.report,same["report_id"]); self.assertEqual("2026-10-01",same["reserved_until"])
        clash=self.db.register_identifier(self.report2,"CVE-2026-0001","2026-11-01","https://example.com/a2",self.coord,as_of="2026-09-03")
        self.assertTrue(clash["duplicate"]); self.assertEqual(self.report,clash["report_id"])
        conflicts=self.db.identifier_conflicts()
        self.assertEqual(1,len(conflicts))
        self.assertEqual("CVE-2026-0001",conflicts[0]["identifier"])
        self.assertEqual(self.report2,conflicts[0]["attempted_report_id"]); self.assertEqual(self.report,conflicts[0]["owner_report_id"])
    def test_expired_cannot_publish_until_renewed_and_renew_keeps_both_deadlines(self):
        self.db.register_identifier(self.report,"CVE-2026-0002","2026-09-10","https://example.com/b1",self.coord,as_of="2026-09-01")
        expired=self.db.identifier_expiring(within_days=30,as_of="2026-09-27")
        self.assertTrue(expired[0]["expired"]); self.assertEqual(-17,expired[0]["days_left"])
        with self.assertRaisesRegex(DomainError,"到期"):
            self.db.publish_identifier("CVE-2026-0002",self.coord,as_of="2026-09-27")
        renewed=self.db.renew_identifier("CVE-2026-0002","2026-12-01",self.coord,as_of="2026-09-27")
        self.assertEqual("2026-12-01",renewed["reserved_until"])
        renews=[e for e in self.db.identifier_events() if e["action"]=="renew"]
        self.assertEqual("2026-09-10",renews[0]["old_until"]); self.assertEqual("2026-12-01",renews[0]["new_until"])
        published=self.db.publish_identifier("CVE-2026-0002",self.coord,as_of="2026-10-01")
        self.assertEqual("published",published["status"]); self.assertEqual("2026-10-01",published["published_at"])
        with self.assertRaisesRegex(DomainError,"再次披露"):
            self.db.publish_identifier("CVE-2026-0002",self.coord,as_of="2026-10-02")
    def test_withdraw_frees_identifier_and_views(self):
        self.db.register_identifier(self.report,"CVE-2026-0003","2026-10-05","https://example.com/c1",self.coord,as_of="2026-09-20")
        expiring=self.db.identifier_expiring(within_days=30,as_of="2026-09-27")
        self.assertEqual(["CVE-2026-0003"],[r["identifier"] for r in expiring]); self.assertEqual(8,expiring[0]["days_left"])
        self.db.withdraw_identifier("CVE-2026-0003",self.coord,"编号分配错误")
        reg=self.db.register_identifier(self.report2,"CVE-2026-0003","2026-11-01","https://example.com/c2",self.coord,as_of="2026-09-27")
        self.assertFalse(reg["duplicate"]); self.assertEqual(self.report2,reg["report_id"])
        actions=[e["action"] for e in self.db.identifier_events()]
        self.assertEqual(["register","withdraw","register"],actions)
        overview=self.db.identifier_overview(as_of="2026-09-27")
        self.assertEqual(2,len(overview["registry"])); self.assertEqual([],overview["conflicts"])
    def test_only_coordinator_manages_identifiers(self):
        with self.assertRaisesRegex(DomainError,"协调员"):
            self.db.register_identifier(self.report,"CVE-2026-0004","2026-10-01","https://example.com/d1",self.maint,as_of="2026-09-01")

if __name__=="__main__": unittest.main()
