from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta
from pathlib import Path


class DomainError(ValueError):
    """Business rule violation."""


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
            CREATE TABLE IF NOT EXISTS identifier_registry (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              identifier TEXT NOT NULL,
              report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
              advisory_url TEXT NOT NULL,
              reserved_until TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'reserved' CHECK(status IN ('reserved','published','withdrawn')),
              created_by INTEGER NOT NULL REFERENCES users(id),
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              published_at TEXT,
              withdrawn_at TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_identifier_active
              ON identifier_registry(identifier) WHERE status IN ('reserved','published');
            CREATE TABLE IF NOT EXISTS identifier_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              identifier TEXT NOT NULL,
              registry_id INTEGER REFERENCES identifier_registry(id) ON DELETE SET NULL,
              report_id INTEGER,
              action TEXT NOT NULL CHECK(action IN ('register','duplicate','renew','publish','withdraw','blocked')),
              old_until TEXT,
              new_until TEXT,
              detail TEXT NOT NULL DEFAULT '',
              actor_id INTEGER NOT NULL REFERENCES users(id),
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
        self.register_identifier(
            report, "CVE-2026-44113", (datetime.now().date() + timedelta(days=33)).isoformat(),
            "https://example.com/advisories/gateway-auth-bypass", coordinator,
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
        return payload

    def set_status(self, report_id: int, new_status: str, user_id: int, note: str = "") -> None:
        if not self.can_view(report_id, user_id):
            raise DomainError("无权修改该报告")
        report = self.conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        user = self._user(user_id)
        if user["role"] == "reporter" and new_status != "rejected":
            raise DomainError("报告人不能推进协调状态")
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

    # ---- 公开编号台账 ----

    @staticmethod
    def _normalize_identifier(identifier: str) -> str:
        return identifier.strip().upper()

    @staticmethod
    def _as_of_date(as_of: str | None) -> date:
        if not as_of:
            return datetime.now().date()
        try:
            return datetime.strptime(as_of, "%Y-%m-%d").date()
        except ValueError as exc:
            raise DomainError("日期必须使用 YYYY-MM-DD") from exc

    def _active_identifier(self, identifier: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM identifier_registry WHERE identifier=? AND status IN ('reserved','published')",
            (identifier,),
        ).fetchone()

    def _identifier_payload(self, row: sqlite3.Row, duplicate: bool = False) -> dict:
        report = self.conn.execute("SELECT public_id,title FROM reports WHERE id=?", (row["report_id"],)).fetchone()
        payload = dict(row)
        payload["report_public_id"] = report["public_id"]
        payload["report_title"] = report["title"]
        payload["duplicate"] = duplicate
        return payload

    def _log_identifier_event(self, identifier: str, registry_id: int | None, report_id: int | None,
                              action: str, actor_id: int, old_until: str | None = None,
                              new_until: str | None = None, detail: str = "") -> None:
        self.conn.execute(
            "INSERT INTO identifier_events(identifier,registry_id,report_id,action,old_until,new_until,detail,actor_id,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (identifier, registry_id, report_id, action, old_until, new_until, detail, actor_id, datetime.now().isoformat()),
        )

    def register_identifier(self, report_id: int, identifier: str, reserved_until: str,
                            advisory_url: str, coordinator_id: int, as_of: str | None = None) -> dict:
        actor = self._user(coordinator_id)
        if actor["role"] != "coordinator":
            raise DomainError("只有协调员可以登记公开编号")
        if not self.conn.execute("SELECT 1 FROM reports WHERE id=?", (report_id,)).fetchone():
            raise DomainError("报告不存在")
        ident = self._normalize_identifier(identifier)
        if not ident or not advisory_url.strip():
            raise DomainError("公开编号和公告地址不能为空")
        try:
            until = datetime.strptime(reserved_until, "%Y-%m-%d").date()
        except ValueError as exc:
            raise DomainError("预留到期日必须使用 YYYY-MM-DD") from exc
        if until < self._as_of_date(as_of):
            raise DomainError("预留到期日不能早于今天")
        now = datetime.now().isoformat()
        with self.transaction():
            existing = self._active_identifier(ident)
            if existing:
                detail = "重复登记，返回已有报告"
                if existing["report_id"] != report_id:
                    detail = f"编号冲突：编号仍归属报告 {existing['report_id']}"
                self._log_identifier_event(ident, existing["id"], report_id, "duplicate", coordinator_id, detail=detail)
                return self._identifier_payload(existing, duplicate=True)
            try:
                cur = self.conn.execute(
                    "INSERT INTO identifier_registry(identifier,report_id,advisory_url,reserved_until,created_by,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (ident, report_id, advisory_url.strip(), reserved_until, coordinator_id, now, now),
                )
            except sqlite3.IntegrityError:
                existing = self._active_identifier(ident)
                self._log_identifier_event(ident, existing["id"], report_id, "duplicate", coordinator_id, detail="重复登记，返回已有报告")
                return self._identifier_payload(existing, duplicate=True)
            self._log_identifier_event(ident, int(cur.lastrowid), report_id, "register", coordinator_id, new_until=reserved_until)
            row = self.conn.execute("SELECT * FROM identifier_registry WHERE id=?", (cur.lastrowid,)).fetchone()
            return self._identifier_payload(row)

    def renew_identifier(self, identifier: str, new_until: str, coordinator_id: int, as_of: str | None = None) -> dict:
        actor = self._user(coordinator_id)
        if actor["role"] != "coordinator":
            raise DomainError("只有协调员可以续期公开编号")
        ident = self._normalize_identifier(identifier)
        row = self._active_identifier(ident)
        if not row:
            raise DomainError("编号不存在或已撤回")
        if row["status"] != "reserved":
            raise DomainError("已公开的编号不能续期")
        try:
            new_date = datetime.strptime(new_until, "%Y-%m-%d").date()
            old_date = datetime.strptime(row["reserved_until"], "%Y-%m-%d").date()
        except ValueError as exc:
            raise DomainError("预留到期日必须使用 YYYY-MM-DD") from exc
        if new_date <= old_date:
            raise DomainError("新预留到期日必须晚于当前到期日")
        if new_date < self._as_of_date(as_of):
            raise DomainError("新预留到期日不能早于今天")
        with self.transaction():
            self.conn.execute(
                "UPDATE identifier_registry SET reserved_until=?,updated_at=? WHERE id=?",
                (new_until, datetime.now().isoformat(), row["id"]),
            )
            self._log_identifier_event(ident, row["id"], row["report_id"], "renew", coordinator_id,
                                       old_until=row["reserved_until"], new_until=new_until,
                                       detail=f"预留期 {row['reserved_until']} 延至 {new_until}")
        return self._identifier_payload(self._active_identifier(ident))

    def publish_identifier(self, identifier: str, coordinator_id: int, as_of: str | None = None) -> dict:
        actor = self._user(coordinator_id)
        if actor["role"] != "coordinator":
            raise DomainError("只有协调员可以披露公开编号")
        ident = self._normalize_identifier(identifier)
        row = self._active_identifier(ident)
        if not row:
            raise DomainError("编号不存在或已撤回")
        if row["status"] == "published":
            raise DomainError("该编号已公开，不能再次披露")
        today = self._as_of_date(as_of)
        until = datetime.strptime(row["reserved_until"], "%Y-%m-%d").date()
        if today > until:
            with self.transaction():
                self._log_identifier_event(ident, row["id"], row["report_id"], "blocked", coordinator_id,
                                           detail=f"预留已于 {row['reserved_until']} 到期且未续期")
            raise DomainError(f"预留已于 {row['reserved_until']} 到期且未续期，不能披露")
        when = today.isoformat()
        with self.transaction():
            self.conn.execute(
                "UPDATE identifier_registry SET status='published',published_at=?,updated_at=? WHERE id=?",
                (when, datetime.now().isoformat(), row["id"]),
            )
            self._log_identifier_event(ident, row["id"], row["report_id"], "publish", coordinator_id,
                                       detail=f"编号公开，公告地址 {row['advisory_url']}")
        return self._identifier_payload(self._active_identifier(ident))

    def withdraw_identifier(self, identifier: str, coordinator_id: int, reason: str = "") -> dict:
        actor = self._user(coordinator_id)
        if actor["role"] != "coordinator":
            raise DomainError("只有协调员可以撤回公开编号")
        ident = self._normalize_identifier(identifier)
        row = self._active_identifier(ident)
        if not row:
            raise DomainError("编号不存在或已撤回")
        if row["status"] == "published":
            raise DomainError("已公开的编号不能撤回")
        now = datetime.now().isoformat()
        with self.transaction():
            self.conn.execute(
                "UPDATE identifier_registry SET status='withdrawn',withdrawn_at=?,updated_at=? WHERE id=?",
                (now, now, row["id"]),
            )
            self._log_identifier_event(ident, row["id"], row["report_id"], "withdraw", coordinator_id,
                                       detail=reason.strip() or "协调员撤回")
        row = self.conn.execute("SELECT * FROM identifier_registry WHERE id=?", (row["id"],)).fetchone()
        return self._identifier_payload(row)

    def identifier_registry(self, as_of: str | None = None) -> list[dict]:
        today = self._as_of_date(as_of)
        rows = self.conn.execute(
            "SELECT i.*,r.public_id AS report_public_id,r.title AS report_title,u.name AS created_by_name "
            "FROM identifier_registry i JOIN reports r ON r.id=i.report_id JOIN users u ON u.id=i.created_by ORDER BY i.id"
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            until = datetime.strptime(item["reserved_until"], "%Y-%m-%d").date()
            item["expired"] = item["status"] == "reserved" and until < today
            result.append(item)
        return result

    def identifier_conflicts(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT e.identifier,e.report_id AS attempted_report_id,i.report_id AS owner_report_id,"
            "e.detail,e.created_at,r1.public_id AS attempted_public_id,r2.public_id AS owner_public_id "
            "FROM identifier_events e JOIN identifier_registry i ON i.id=e.registry_id "
            "JOIN reports r1 ON r1.id=e.report_id JOIN reports r2 ON r2.id=i.report_id "
            "WHERE e.action='duplicate' AND e.report_id!=i.report_id ORDER BY e.id DESC"
        )]

    def identifier_expiring(self, within_days: int = 14, as_of: str | None = None) -> list[dict]:
        today = self._as_of_date(as_of)
        horizon = (today + timedelta(days=within_days)).isoformat()
        rows = self.conn.execute(
            "SELECT i.*,r.public_id AS report_public_id,r.title AS report_title FROM identifier_registry i "
            "JOIN reports r ON r.id=i.report_id WHERE i.status='reserved' AND i.reserved_until<=? ORDER BY i.reserved_until",
            (horizon,),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            until = datetime.strptime(item["reserved_until"], "%Y-%m-%d").date()
            item["days_left"] = (until - today).days
            item["expired"] = until < today
            result.append(item)
        return result

    def identifier_events(self, limit: int = 50) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT e.*,u.name AS actor_name FROM identifier_events e JOIN users u ON u.id=e.actor_id "
            "ORDER BY e.id DESC LIMIT ?", (limit,),
        )]

    def identifier_overview(self, as_of: str | None = None, within_days: int = 14) -> dict:
        return {
            "registry": self.identifier_registry(as_of),
            "conflicts": self.identifier_conflicts(),
            "expiring": self.identifier_expiring(within_days, as_of),
            "events": self.identifier_events(),
        }

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
