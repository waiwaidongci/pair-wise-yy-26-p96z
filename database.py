from __future__ import annotations

import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from pathlib import Path


class DomainError(ValueError):
    """Business rule violation."""


class PublicIdConflict(DomainError):
    """Public identifier already held by another report."""

    def __init__(self, message: str, holder: dict) -> None:
        super().__init__(message)
        self.holder = holder


STATUS_TRANSITIONS = {
    "new": {"triaged", "rejected"},
    "triaged": {"fixing", "rejected"},
    "fixing": {"resolved", "rejected"},
    "resolved": {"published", "fixing"},
    "published": set(),
    "rejected": set(),
}


class VulnerabilityDB:
    """Embargo-aware vulnerability coordination service."""

    def __init__(self, path: str = "vulnerability.db") -> None:
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        if path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self._schema()

    def close(self) -> None:
        self.conn.close()

    @contextmanager
    def transaction(self):
        try:
            self.conn.execute("BEGIN IMMEDIATE")
            yield
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise

    def _schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL UNIQUE,
              role TEXT NOT NULL CHECK(role IN ('coordinator','maintainer','reporter')),
              organization TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS products (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL UNIQUE,
              owner TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS reports (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              public_id TEXT NOT NULL UNIQUE,
              title TEXT NOT NULL,
              product_id INTEGER NOT NULL REFERENCES products(id),
              reporter_id INTEGER NOT NULL REFERENCES users(id),
              summary TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'new'
                CHECK(status IN ('new','triaged','fixing','resolved','published','rejected')),
              confidential_until TEXT NOT NULL,
              public_at TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS affected_versions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
              version_key TEXT NOT NULL,
              details TEXT NOT NULL DEFAULT '',
              UNIQUE(report_id, version_key)
            );
            CREATE TABLE IF NOT EXISTS report_members (
              report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
              user_id INTEGER NOT NULL REFERENCES users(id),
              member_role TEXT NOT NULL CHECK(member_role IN ('coordinator','maintainer')),
              added_by INTEGER NOT NULL REFERENCES users(id),
              PRIMARY KEY(report_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS evidence (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
              name TEXT NOT NULL,
              content TEXT NOT NULL,
              classification TEXT NOT NULL CHECK(classification IN ('private','coordinator')),
              uploaded_by INTEGER NOT NULL REFERENCES users(id),
              created_at TEXT NOT NULL,
              UNIQUE(report_id, name)
            );
            CREATE TABLE IF NOT EXISTS fix_plans (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              report_id INTEGER NOT NULL UNIQUE REFERENCES reports(id) ON DELETE CASCADE,
              maintainer_id INTEGER NOT NULL REFERENCES users(id),
              plan TEXT NOT NULL,
              target_date TEXT,
              status TEXT NOT NULL DEFAULT 'proposed' CHECK(status IN ('proposed','accepted','done')),
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS status_history (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
              old_status TEXT,
              new_status TEXT NOT NULL,
              changed_by INTEGER NOT NULL REFERENCES users(id),
              note TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS extensions (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
              old_deadline TEXT NOT NULL,
              new_deadline TEXT NOT NULL,
              reason TEXT NOT NULL,
              coordinator_id INTEGER NOT NULL REFERENCES users(id),
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS notifications (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
              user_id INTEGER NOT NULL REFERENCES users(id),
              kind TEXT NOT NULL,
              message TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS advisory_drafts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              report_id INTEGER NOT NULL UNIQUE REFERENCES reports(id) ON DELETE CASCADE,
              content TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published')),
              created_by INTEGER NOT NULL REFERENCES users(id),
              created_at TEXT NOT NULL,
              published_at TEXT
            );
            CREATE TABLE IF NOT EXISTS public_id_registrations (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              identifier TEXT NOT NULL,
              report_id INTEGER NOT NULL REFERENCES reports(id),
              reserved_until TEXT NOT NULL,
              advisory_url TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL DEFAULT 'reserved' CHECK(status IN ('reserved','renewed','withdrawn')),
              created_by INTEGER NOT NULL REFERENCES users(id),
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_public_id_active
              ON public_id_registrations(identifier) WHERE status != 'withdrawn';
            CREATE INDEX IF NOT EXISTS idx_public_id_report
              ON public_id_registrations(report_id);
            CREATE TABLE IF NOT EXISTS public_id_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              identifier TEXT NOT NULL,
              registration_id INTEGER REFERENCES public_id_registrations(id),
              report_id INTEGER REFERENCES reports(id),
              action TEXT NOT NULL CHECK(action IN ('register','conflict','renew','withdraw','publish_block')),
              detail TEXT NOT NULL DEFAULT '',
              old_deadline TEXT,
              new_deadline TEXT,
              advisory_url TEXT NOT NULL DEFAULT '',
              actor_id INTEGER REFERENCES users(id),
              created_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def seed_demo(self) -> None:
        if self.conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return
        reporter = self.add_user("安全研究员", "reporter", "独立研究")
        coordinator = self.add_user("协调员", "coordinator", "安全响应中心")
        maintainer = self.add_user("维护者", "maintainer", "示例项目组")
        product = self.add_product("示例网关", "示例项目组")
        report = self.create_report("网关鉴权绕过", product, reporter, "特制请求可跳过鉴权。", "2026-10-30", ["3.2.0"], "仅影响 3.2.0")
        self.add_member(report, maintainer, "maintainer", coordinator)
        self.add_evidence(report, "请求样例", "GET /admin HTTP/1.1\nX-Test: bypass", "private", reporter)
        self.set_status(report, "triaged", coordinator, "已确认复现")
        self.set_fix_plan(report, maintainer, "增加鉴权前置校验并补充回归测试", "2026-10-10")
        self.register_public_id(
            "CVE-2026-10001", report, (date.today() + timedelta(days=5)).isoformat(),
            "https://example.example/advisories/CVE-2026-10001", coordinator,
        )

    def add_user(self, name: str, role: str, organization: str = "") -> int:
        if not name.strip() or role not in {"coordinator", "maintainer", "reporter"}:
            raise DomainError("用户名或角色无效")
        with self.transaction():
            try:
                cur = self.conn.execute("INSERT INTO users(name,role,organization) VALUES(?,?,?)", (name.strip(), role, organization.strip()))
            except sqlite3.IntegrityError as exc:
                raise DomainError("用户名已存在") from exc
        return int(cur.lastrowid)

    def add_product(self, name: str, owner: str = "") -> int:
        if not name.strip():
            raise DomainError("产品名称不能为空")
        with self.transaction():
            try:
                cur = self.conn.execute("INSERT INTO products(name,owner) VALUES(?,?)", (name.strip(), owner.strip()))
            except sqlite3.IntegrityError as exc:
                raise DomainError("产品已存在") from exc
        return int(cur.lastrowid)

    def _user(self, user_id: int) -> sqlite3.Row:
        user = self.conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not user:
            raise DomainError("用户不存在")
        return user

    def find_duplicate_reports(self, product_id: int, version_key: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT r.id,r.public_id,r.title,r.status,v.version_key FROM reports r "
            "JOIN affected_versions v ON v.report_id=r.id "
            "WHERE r.product_id=? AND v.version_key=? AND r.status NOT IN ('published','rejected') ORDER BY r.id",
            (product_id, version_key.strip()),
        ).fetchall()
        return [dict(row) for row in rows]

    def create_report(self, title: str, product_id: int, reporter_id: int, summary: str,
                      confidential_until: str, versions: list[str], version_details: str = "",
                      allow_duplicate: bool = False) -> int:
        reporter = self._user(reporter_id)
        if reporter["role"] != "reporter":
            raise DomainError("只有报告人可以创建漏洞报告")
        if not title.strip() or not summary.strip() or not versions:
            raise DomainError("标题、摘要和受影响版本不能为空")
        try:
            deadline = datetime.strptime(confidential_until, "%Y-%m-%d").date()
        except ValueError as exc:
            raise DomainError("保密期限必须使用 YYYY-MM-DD") from exc
        if not self.conn.execute("SELECT 1 FROM products WHERE id=?", (product_id,)).fetchone():
            raise DomainError("产品不存在")
        duplicates = []
        for version in versions:
            duplicates.extend(self.find_duplicate_reports(product_id, version))
        if duplicates and not allow_duplicate:
            ids = ", ".join(row["public_id"] for row in duplicates)
            raise DomainError(f"可能重复的报告: {ids}")
        created = datetime.now().isoformat()
        with self.transaction():
            temp_id = self.conn.execute("SELECT COALESCE(MAX(id),0)+1 FROM reports").fetchone()[0]
            public_id = f"VULN-{deadline.year}-{temp_id:04d}"
            cur = self.conn.execute(
                "INSERT INTO reports(public_id,title,product_id,reporter_id,summary,confidential_until,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (public_id, title.strip(), product_id, reporter_id, summary.strip(), confidential_until, created, created),
            )
            report_id = int(cur.lastrowid)
            for version in versions:
                if not str(version).strip():
                    raise DomainError("版本号不能为空")
                self.conn.execute(
                    "INSERT INTO affected_versions(report_id,version_key,details) VALUES(?,?,?)",
                    (report_id, str(version).strip(), version_details.strip()),
                )
            self.conn.execute(
                "INSERT INTO status_history(report_id,old_status,new_status,changed_by,note,created_at) VALUES(?,?,?,?,?,?)",
                (report_id, None, "new", reporter_id, "报告创建", created),
            )
        return report_id

    def add_member(self, report_id: int, user_id: int, member_role: str, added_by: int) -> None:
        actor, user, report = self._user(added_by), self._user(user_id), self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not report:
            raise DomainError("报告不存在")
        if actor["role"] != "coordinator" or member_role not in {"coordinator", "maintainer"}:
            raise DomainError("只有协调员可以添加协调员或维护者")
        if member_role == "maintainer" and user["role"] != "maintainer":
            raise DomainError("指定用户不是维护者")
        with self.transaction():
            self.conn.execute(
                "INSERT OR REPLACE INTO report_members(report_id,user_id,member_role,added_by) VALUES(?,?,?,?)",
                (report_id, user_id, member_role, added_by),
            )
            self._notify(report_id, user_id, "membership", f"你已被加入漏洞 {report['public_id']}")

    def _member(self, report_id: int, user_id: int) -> bool:
        return bool(self.conn.execute("SELECT 1 FROM report_members WHERE report_id=? AND user_id=?", (report_id, user_id)).fetchone())

    def can_view(self, report_id: int, user_id: int) -> bool:
        report = self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not report:
            return False
        user = self.conn.execute("SELECT role FROM users WHERE id=?", (user_id,)).fetchone()
        if user and user["role"] == "coordinator":
            return True
        return bool(user_id == report["reporter_id"] or self._member(report_id, user_id))

    def add_evidence(self, report_id: int, name: str, content: str, classification: str, uploaded_by: int) -> int:
        if not self.can_view(report_id, uploaded_by):
            raise DomainError("无权向该报告添加材料")
        if classification not in {"private", "coordinator"} or not name.strip() or not content:
            raise DomainError("材料名称、内容或密级无效")
        user = self._user(uploaded_by)
        if classification == "coordinator" and user["role"] not in {"coordinator", "reporter"}:
            raise DomainError("维护者不能提交协调员专用材料")
        with self.transaction():
            try:
                cur = self.conn.execute(
                    "INSERT INTO evidence(report_id,name,content,classification,uploaded_by,created_at) VALUES(?,?,?,?,?,?)",
                    (report_id, name.strip(), content, classification, uploaded_by, datetime.now().isoformat()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("同一报告中的材料名称不能重复") from exc
        return int(cur.lastrowid)

    def get_report_for_user(self, report_id: int, user_id: int) -> dict:
        if not self.can_view(report_id, user_id):
            raise DomainError("无权查看该漏洞报告")
        report = self.conn.execute(
            "SELECT r.*,p.name AS product_name,u.name AS reporter_name FROM reports r "
            "JOIN products p ON p.id=r.product_id JOIN users u ON u.id=r.reporter_id WHERE r.id=?", (report_id,)
        ).fetchone()
        if not report:
            raise DomainError("报告不存在")
        user = self._user(user_id)
        evidence = []
        for row in self.conn.execute("SELECT * FROM evidence WHERE report_id=? ORDER BY id", (report_id,)).fetchall():
            if row["classification"] == "coordinator" and user["role"] not in {"coordinator", "reporter"}:
                continue
            evidence.append(dict(row))
        payload = dict(report)
        payload["versions"] = [dict(r) for r in self.conn.execute("SELECT * FROM affected_versions WHERE report_id=? ORDER BY id", (report_id,))]
        payload["members"] = [dict(r) for r in self.conn.execute(
            "SELECT m.*,u.name,u.role FROM report_members m JOIN users u ON u.id=m.user_id WHERE m.report_id=?", (report_id,)
        )]
        payload["evidence"] = evidence
        payload["fix_plan"] = dict(self.conn.execute("SELECT * FROM fix_plans WHERE report_id=?", (report_id,)).fetchone() or {})
        payload["history"] = [dict(r) for r in self.conn.execute("SELECT * FROM status_history WHERE report_id=? ORDER BY id", (report_id,))]
        payload["extensions"] = [dict(r) for r in self.conn.execute("SELECT * FROM extensions WHERE report_id=? ORDER BY id", (report_id,))]
        payload["public_id_registration"] = self.active_public_id_for_report(report_id)
        return payload

    def set_status(self, report_id: int, new_status: str, user_id: int, note: str = "") -> None:
        if not self.can_view(report_id, user_id):
            raise DomainError("无权修改该报告")
        report = self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        user = self._user(user_id)
        if user["role"] == "reporter" and new_status != "rejected":
            raise DomainError("报告人不能推进协调状态")
        if new_status == "published":
            self._assert_disclosable(report_id, date.today())
        if new_status not in STATUS_TRANSITIONS.get(report["status"], set()):
            raise DomainError(f"状态不能从 {report['status']} 变为 {new_status}")
        now = datetime.now().isoformat()
        with self.transaction():
            self.conn.execute("UPDATE reports SET status=?,updated_at=? WHERE id=?", (new_status, now, report_id))
            self.conn.execute(
                "INSERT INTO status_history(report_id,old_status,new_status,changed_by,note,created_at) VALUES(?,?,?,?,?,?)",
                (report_id, report["status"], new_status, user_id, note.strip(), now),
            )
            for member in self.conn.execute("SELECT user_id FROM report_members WHERE report_id=?", (report_id,)).fetchall():
                self._notify(report_id, member["user_id"], "status", f"报告状态更新为 {new_status}")
        if new_status == "published":
            self._publish_advisory_if_ready(report_id, user_id, now)

    def set_fix_plan(self, report_id: int, maintainer_id: int, plan: str, target_date: str | None = None) -> int:
        user = self._user(maintainer_id)
        if user["role"] != "maintainer" or not self._member(report_id, maintainer_id):
            raise DomainError("只有该报告的维护者可以提交修复计划")
        if user["role"] == "maintainer" and not self.can_view(report_id, maintainer_id):
            raise DomainError("无权修改该报告")
        if not plan.strip():
            raise DomainError("修复计划不能为空")
        if target_date:
            try:
                datetime.strptime(target_date, "%Y-%m-%d")
            except ValueError as exc:
                raise DomainError("目标日期必须使用 YYYY-MM-DD") from exc
        with self.transaction():
            try:
                cur = self.conn.execute(
                    "INSERT INTO fix_plans(report_id,maintainer_id,plan,target_date,created_at) VALUES(?,?,?,?,?)",
                    (report_id, maintainer_id, plan.strip(), target_date, datetime.now().isoformat()),
                )
            except sqlite3.IntegrityError:
                cur = self.conn.execute(
                    "UPDATE fix_plans SET maintainer_id=?,plan=?,target_date=?,status='proposed',created_at=? WHERE report_id=?",
                    (maintainer_id, plan.strip(), target_date, datetime.now().isoformat(), report_id),
                )
                plan_id = self.conn.execute("SELECT id FROM fix_plans WHERE report_id=?", (report_id,)).fetchone()["id"]
            else:
                plan_id = int(cur.lastrowid)
        return int(plan_id)

    def extend_embargo(self, report_id: int, new_deadline: str, reason: str, coordinator_id: int) -> int:
        actor = self._user(coordinator_id)
        report = self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not report or actor["role"] != "coordinator":
            raise DomainError("只有协调员可以延期")
        try:
            new_date = datetime.strptime(new_deadline, "%Y-%m-%d").date()
            old_date = datetime.strptime(report["confidential_until"], "%Y-%m-%d").date()
        except ValueError as exc:
            raise DomainError("日期必须使用 YYYY-MM-DD") from exc
        if new_date <= old_date:
            raise DomainError("新截止日期必须晚于当前日期")
        if len(reason.strip()) < 5:
            raise DomainError("延期理由至少5个字符")
        if report["status"] == "published":
            raise DomainError("已披露报告不能延期")
        with self.transaction():
            cur = self.conn.execute(
                "INSERT INTO extensions(report_id,old_deadline,new_deadline,reason,coordinator_id,created_at) VALUES(?,?,?,?,?,?)",
                (report_id, report["confidential_until"], new_deadline, reason.strip(), coordinator_id, datetime.now().isoformat()),
            )
            self.conn.execute("UPDATE reports SET confidential_until=?,updated_at=? WHERE id=?", (new_deadline, datetime.now().isoformat(), report_id))
            for member in self.conn.execute("SELECT user_id FROM report_members WHERE report_id=?", (report_id,)).fetchall():
                self._notify(report_id, member["user_id"], "extension", f"保密期延长至 {new_deadline}: {reason.strip()}")
        return int(cur.lastrowid)

    def create_advisory_draft(self, report_id: int, content: str, user_id: int) -> int:
        if not self.can_view(report_id, user_id):
            raise DomainError("无权创建公告")
        user = self._user(user_id)
        if user["role"] not in {"coordinator", "maintainer"}:
            raise DomainError("只有协调员或维护者可以创建公告草稿")
        report = self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if report["status"] not in {"fixing", "resolved"}:
            raise DomainError("只有修复中或已解决报告可以创建公告")
        if len(content.strip()) < 10:
            raise DomainError("公告内容过短")
        with self.transaction():
            try:
                cur = self.conn.execute(
                    "INSERT INTO advisory_drafts(report_id,content,created_by,created_at) VALUES(?,?,?,?)",
                    (report_id, content.strip(), user_id, datetime.now().isoformat()),
                )
            except sqlite3.IntegrityError:
                cur = self.conn.execute(
                    "UPDATE advisory_drafts SET content=?,created_by=?,created_at=?,status='draft' WHERE report_id=?",
                    (content.strip(), user_id, datetime.now().isoformat(), report_id),
                )
                draft_id = self.conn.execute("SELECT id FROM advisory_drafts WHERE report_id=?", (report_id,)).fetchone()["id"]
            else:
                draft_id = int(cur.lastrowid)
        return int(draft_id)

    def _publish_advisory_if_ready(self, report_id: int, user_id: int, when: str) -> None:
        draft = self.conn.execute("SELECT * FROM advisory_drafts WHERE report_id=?", (report_id,)).fetchone()
        if not draft:
            raise DomainError("已解决报告必须先生成公告草稿才能发布")
        self.conn.execute(
            "UPDATE advisory_drafts SET status='published',published_at=? WHERE report_id=?", (when, report_id)
        )
        self.conn.execute("UPDATE reports SET public_at=? WHERE id=?", (when, report_id))
        for member in self.conn.execute("SELECT user_id FROM report_members WHERE report_id=?", (report_id,)).fetchall():
            self._notify(report_id, member["user_id"], "published", "漏洞公告已公开")

    def publish_report(self, report_id: int, coordinator_id: int, as_of: str | None = None) -> None:
        actor = self._user(coordinator_id)
        report = self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not report or actor["role"] != "coordinator":
            raise DomainError("只有协调员可以披露报告")
        when = as_of or datetime.now().date().isoformat()
        try:
            now_date = datetime.strptime(when, "%Y-%m-%d").date()
            deadline = datetime.strptime(report["confidential_until"], "%Y-%m-%d").date()
        except ValueError as exc:
            raise DomainError("披露日期必须使用 YYYY-MM-DD") from exc
        if now_date < deadline:
            raise DomainError(f"保密期截至 {report['confidential_until']}，不能提前披露")
        if report["status"] == "published":
            raise DomainError("报告已公开，不能再次披露")
        registration = self.conn.execute(
            "SELECT * FROM public_id_registrations WHERE report_id=? AND status!='withdrawn' "
            "ORDER BY id DESC LIMIT 1",
            (report_id,),
        ).fetchone()
        if registration:
            reserved_until = self._validate_day(registration["reserved_until"], "预留到期日")
            if now_date > reserved_until:
                message = (f"公开编号 {registration['identifier']} 预留已于 "
                           f"{registration['reserved_until']} 到期，续期后才能披露")
                with self.transaction():
                    self._log_public_id_event(
                        registration["identifier"], "publish_block", coordinator_id,
                        registration["id"], report_id, message,
                        registration["reserved_until"], None, registration["advisory_url"],
                    )
                raise DomainError(message)
        if report["status"] != "resolved":
            raise DomainError("只有已解决报告可以披露")
        self.set_status(report_id, "published", coordinator_id, f"公开日期 {when}")

    def get_advisory(self, report_id: int, user_id: int) -> dict:
        report = self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not report:
            raise DomainError("报告不存在")
        if report["status"] != "published" and not self.can_view(report_id, user_id):
            raise DomainError("公告尚未公开")
        draft = self.conn.execute("SELECT * FROM advisory_drafts WHERE report_id=?", (report_id,)).fetchone()
        if not draft:
            raise DomainError("公告尚未生成")
        payload = dict(draft)
        payload["public_id"] = report["public_id"]
        payload["title"] = report["title"]
        payload["summary"] = report["summary"]
        if report["status"] != "published":
            payload["status"] = "draft"
        return payload

    def _validate_identifier(self, identifier: str) -> str:
        value = identifier.strip().upper()
        if not re.fullmatch(r"[A-Z0-9][A-Z0-9._-]{2,63}", value):
            raise DomainError("公开编号需为 3-64 位字母、数字或 ._- 且以字母数字开头")
        return value

    def _validate_day(self, value: str, field: str = "日期") -> date:
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError as exc:
            raise DomainError(f"{field}必须使用 YYYY-MM-DD") from exc

    def _validate_advisory_url(self, advisory_url: str) -> str:
        url = advisory_url.strip()
        if not url:
            raise DomainError("公告地址不能为空")
        if not re.fullmatch(r"https?://[^\s]{2,2000}", url):
            raise DomainError("公告地址必须是 http(s) 链接")
        return url

    def _report_or_error(self, report_id: int) -> sqlite3.Row:
        report = self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not report:
            raise DomainError("报告不存在")
        return report

    def _log_public_id_event(self, identifier: str, action: str, actor_id: int,
                             registration_id: int | None = None, report_id: int | None = None,
                             detail: str = "", old_deadline: str | None = None,
                             new_deadline: str | None = None, advisory_url: str = "") -> None:
        self.conn.execute(
            "INSERT INTO public_id_events(identifier,registration_id,report_id,action,detail,"
            "old_deadline,new_deadline,advisory_url,actor_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (identifier, registration_id, report_id, action, detail, old_deadline, new_deadline,
             advisory_url, actor_id, datetime.now().isoformat()),
        )

    def _registration_payload(self, row: sqlite3.Row) -> dict:
        payload = dict(row)
        report = self.conn.execute(
            "SELECT r.id,r.public_id,r.title,r.status,p.name AS product_name FROM reports r "
            "JOIN products p ON p.id=r.product_id WHERE r.id=?",
            (row["report_id"],),
        ).fetchone()
        payload["report"] = dict(report) if report else None
        return payload

    def register_public_id(self, identifier: str, report_id: int, reserved_until: str,
                           advisory_url: str, coordinator_id: int) -> dict:
        """登记公开编号；编号已被未撤回登记持有时返回已有报告并记录冲突。"""
        actor = self._user(coordinator_id)
        if actor["role"] != "coordinator":
            raise DomainError("只有协调员可以登记公开编号")
        public_id = self._validate_identifier(identifier)
        deadline = self._validate_day(reserved_until, "预留到期日")
        url = self._validate_advisory_url(advisory_url)
        report = self._report_or_error(report_id)
        if report["status"] == "published":
            raise DomainError("报告已公开，不能再登记公开编号")
        if report["status"] == "rejected":
            raise DomainError("报告已拒绝，不能登记公开编号")
        now = datetime.now().isoformat()
        conflict: tuple[sqlite3.Row, sqlite3.Row] | None = None
        registration_id: int | None = None
        with self.transaction():
            existing = self.conn.execute(
                "SELECT * FROM public_id_registrations WHERE identifier=? AND status!='withdrawn'",
                (public_id,),
            ).fetchone()
            if existing:
                if existing["report_id"] == report_id:
                    return self._registration_payload(existing)
                conflict = (existing, self._report_or_error(existing["report_id"]))
            else:
                cur = self.conn.execute(
                    "INSERT INTO public_id_registrations(identifier,report_id,reserved_until,advisory_url,"
                    "status,created_by,created_at,updated_at) VALUES(?,?,?,?, 'reserved',?,?,?)",
                    (public_id, report_id, deadline.isoformat(), url, coordinator_id, now, now),
                )
                registration_id = int(cur.lastrowid)
                self._log_public_id_event(
                    public_id, "register", coordinator_id, registration_id, report_id,
                    "登记公开编号", None, deadline.isoformat(), url,
                )
                self._notify(report_id, coordinator_id, "public_id", f"公开编号 {public_id} 已登记")
        if conflict is not None:
            # 冲突登记被拒绝，但处理记录必须保留，因此在独立事务中落库
            existing, holder = conflict
            with self.transaction():
                self._log_public_id_event(
                    public_id, "conflict", coordinator_id, existing["id"], report_id,
                    f"报告 {report['public_id']} 重复登记，编号已归 {holder['public_id']}",
                    existing["reserved_until"], None, url,
                )
            raise PublicIdConflict(
                f"公开编号 {public_id} 已登记给报告 {holder['public_id']}",
                self._registration_payload(existing),
            )
        return self._registration_payload(
            self.conn.execute("SELECT * FROM public_id_registrations WHERE id=?", (registration_id,)).fetchone()
        )

    def renew_public_id(self, registration_id: int, new_deadline: str, coordinator_id: int,
                        reason: str = "", advisory_url: str | None = None) -> dict:
        """续期预留，保留新旧期限；只有协调员可操作。"""
        actor = self._user(coordinator_id)
        if actor["role"] != "coordinator":
            raise DomainError("只有协调员可以续期公开编号")
        if len(reason.strip()) < 5:
            raise DomainError("续期理由至少5个字符")
        row = self.conn.execute(
            "SELECT * FROM public_id_registrations WHERE id=?", (registration_id,)
        ).fetchone()
        if not row:
            raise DomainError("编号登记不存在")
        if row["status"] == "withdrawn":
            raise DomainError("登记已撤回，不能续期")
        report = self._report_or_error(row["report_id"])
        if report["status"] == "published":
            raise DomainError("报告已公开，不能续期")
        new_date = self._validate_day(new_deadline, "新预留到期日")
        old_date = self._validate_day(row["reserved_until"], "原预留到期日")
        if new_date <= old_date:
            raise DomainError("新预留到期日必须晚于当前预留到期日")
        url = self._validate_advisory_url(advisory_url if advisory_url is not None else row["advisory_url"])
        now = datetime.now().isoformat()
        with self.transaction():
            self.conn.execute(
                "UPDATE public_id_registrations SET reserved_until=?,advisory_url=?,status='renewed',updated_at=? WHERE id=?",
                (new_date.isoformat(), url, now, registration_id),
            )
            self._log_public_id_event(
                row["identifier"], "renew", coordinator_id, registration_id, row["report_id"],
                reason.strip(), row["reserved_until"], new_date.isoformat(), url,
            )
            self._notify(row["report_id"], coordinator_id, "public_id",
                         f"公开编号 {row['identifier']} 预留续期至 {new_date.isoformat()}")
        return self._registration_payload(
            self.conn.execute("SELECT * FROM public_id_registrations WHERE id=?", (registration_id,)).fetchone()
        )

    def withdraw_public_id(self, registration_id: int, coordinator_id: int, reason: str = "") -> dict:
        """撤回登记以释放编号，供其他报告使用；撤回保留处理记录。"""
        actor = self._user(coordinator_id)
        if actor["role"] != "coordinator":
            raise DomainError("只有协调员可以撤回公开编号")
        row = self.conn.execute(
            "SELECT * FROM public_id_registrations WHERE id=?", (registration_id,)
        ).fetchone()
        if not row:
            raise DomainError("编号登记不存在")
        if row["status"] == "withdrawn":
            raise DomainError("登记已撤回")
        now = datetime.now().isoformat()
        with self.transaction():
            self.conn.execute(
                "UPDATE public_id_registrations SET status='withdrawn',updated_at=? WHERE id=?",
                (now, registration_id),
            )
            self._log_public_id_event(
                row["identifier"], "withdraw", coordinator_id, registration_id, row["report_id"],
                reason.strip(), row["reserved_until"], None, row["advisory_url"],
            )
            self._notify(row["report_id"], coordinator_id, "public_id",
                         f"公开编号 {row['identifier']} 登记已撤回")
        return self._registration_payload(
            self.conn.execute("SELECT * FROM public_id_registrations WHERE id=?", (registration_id,)).fetchone()
        )

    def active_public_id_for_report(self, report_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM public_id_registrations WHERE report_id=? AND status!='withdrawn' "
            "ORDER BY id DESC LIMIT 1",
            (report_id,),
        ).fetchone()
        return self._registration_payload(row) if row else None

    def public_id_ledger(self, within_days: int = 14) -> dict:
        """台账视图：全部登记、冲突编号、即将到期项、处理记录。"""
        if within_days < 0:
            raise DomainError("预警天数不能为负")
        today = date.today()
        horizon = today + timedelta(days=within_days)
        registrations = [
            self._registration_payload(row)
            for row in self.conn.execute(
                "SELECT * FROM public_id_registrations ORDER BY id DESC"
            ).fetchall()
        ]
        conflicts = []
        for row in self.conn.execute(
            "SELECT * FROM public_id_events WHERE action='conflict' ORDER BY id DESC"
        ).fetchall():
            event = dict(row)
            holder = self.conn.execute(
                "SELECT g.*,r.public_id AS report_public_id,r.title AS report_title,r.status AS report_status "
                "FROM public_id_registrations g JOIN reports r ON r.id=g.report_id WHERE g.id=?",
                (row["registration_id"],),
            ).fetchone()
            event["holder"] = self._registration_payload(holder) if holder else None
            attempt = self.conn.execute(
                "SELECT id,public_id,title,status FROM reports WHERE id=?", (row["report_id"],)
            ).fetchone()
            event["attempt_report"] = dict(attempt) if attempt else None
            conflicts.append(event)
        expiring = [
            self._registration_payload(row)
            for row in self.conn.execute(
                "SELECT * FROM public_id_registrations WHERE status!='withdrawn' "
                "AND date(reserved_until) BETWEEN date(?) AND date(?) ORDER BY reserved_until, id",
                (today.isoformat(), horizon.isoformat()),
            ).fetchall()
        ]
        events = [
            dict(row)
            for row in self.conn.execute(
                "SELECT e.*,u.name AS actor_name FROM public_id_events e "
                "LEFT JOIN users u ON u.id=e.actor_id ORDER BY e.id DESC"
            ).fetchall()
        ]
        return {
            "today": today.isoformat(),
            "within_days": within_days,
            "registrations": registrations,
            "conflicts": conflicts,
            "expiring": expiring,
            "events": events,
        }

    def _assert_disclosable(self, report_id: int, when: date) -> None:
        """已公开或编号预留到期未续期的报告不能再次披露。"""
        report = self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if report and report["status"] == "published":
            raise DomainError("报告已公开，不能再次披露")
        registration = self.conn.execute(
            "SELECT * FROM public_id_registrations WHERE report_id=? AND status!='withdrawn' "
            "ORDER BY id DESC LIMIT 1",
            (report_id,),
        ).fetchone()
        if registration:
            reserved_until = self._validate_day(registration["reserved_until"], "预留到期日")
            if when > reserved_until:
                raise DomainError(
                    f"公开编号 {registration['identifier']} 预留已于 {registration['reserved_until']} 到期，"
                    "续期后才能披露"
                )

    def _notify(self, report_id: int, user_id: int, kind: str, message: str) -> None:
        self.conn.execute(
            "INSERT INTO notifications(report_id,user_id,kind,message,created_at) VALUES(?,?,?,?,?)",
            (report_id, user_id, kind, message, datetime.now().isoformat()),
        )

    def notifications_for(self, user_id: int) -> list[dict]:
        return [dict(row) for row in self.conn.execute(
            "SELECT n.*,r.public_id FROM notifications n JOIN reports r ON r.id=n.report_id WHERE n.user_id=? ORDER BY n.id DESC",
            (user_id,),
        ).fetchall()]

    def snapshot(self) -> dict:
        return {
            "products": [dict(r) for r in self.conn.execute("SELECT * FROM products ORDER BY id")],
            "reports": [dict(r) for r in self.conn.execute(
                "SELECT r.*,p.name AS product_name,u.name AS reporter_name FROM reports r JOIN products p ON p.id=r.product_id JOIN users u ON u.id=r.reporter_id ORDER BY r.id"
            )],
            "users": [dict(r) for r in self.conn.execute("SELECT id,name,role,organization FROM users ORDER BY id")],
        }
