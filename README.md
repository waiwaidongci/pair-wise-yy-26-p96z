# 开源漏洞披露协作

这是使用 Python 标准库、SQLite 和 `http.server` 实现的保密漏洞协作后台。系统支持报告人、协调员、维护者三种角色，管理受影响产品版本、私密证明材料、保密期限、修复计划、状态历史、延期、通知、公开公告和公开编号台账。

## 启动

```bash
python app.py
```

默认端口 `8113`，页面为 <http://127.0.0.1:8113>。首次启动创建示例网关漏洞。可用环境变量 `PORT` 和 `VULN_DB` 调整端口及数据库位置。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；同时验证外部用户无权查看、相同产品版本会触发重复报告，以及维护者看不到协调员专用材料。公开编号台账覆盖重复登记返回已有报告并记录冲突、到期未续期与已公开编号不能再次披露、续期保留新旧期限、撤回后编号可重新登记，以及冲突、即将到期和处理记录视图。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/publish`
- `POST /api/identifiers`、`POST /api/identifiers/renew`
- `POST /api/identifiers/publish`、`POST /api/identifiers/withdraw`
- `GET /api/identifiers?as_of=...&days=...`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。

公开编号台账为每份报告登记公开编号、预留到期日和公告地址。同一编号在撤回前只归属一份报告，重复登记返回已有报告并记入冲突；预留到期未续期或已公开的编号不能再次披露；续期在处理记录中保留新旧期限。`GET /api/identifiers` 返回完整台账、冲突编号、即将到期项和处理记录，页面底部的"公开编号台账"区块可直接查看和操作。
