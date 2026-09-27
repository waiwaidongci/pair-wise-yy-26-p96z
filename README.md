# 开源漏洞披露协作

这是使用 Python 标准库、SQLite 和 `http.server` 实现的保密漏洞协作后台。系统支持报告人、协调员、维护者三种角色，管理受影响产品版本、私密证明材料、保密期限、修复计划、状态历史、延期、通知和公开公告。

## 启动

```bash
python app.py
```

默认端口 `8113`，页面为 <http://127.0.0.1:8113>。首次启动创建示例网关漏洞。可用环境变量 `PORT` 和 `VULN_DB` 调整端口及数据库位置。

## 测试

```bash
python -m unittest discover -s tests -v
```

测试覆盖：创建报告、加入维护者、分级、提交修复计划、解决、阻止提前披露、到期披露并读取公告；同时验证外部用户无权查看、相同产品版本会触发重复报告，以及维护者看不到协调员专用材料。公开编号台账测试覆盖登记幂等、重复登记返回持有报告、撤回释放编号、续期保留新旧期限、到期未续期拦截披露以及台账视图。

## 接口

- `POST /api/users`、`POST /api/products`、`POST /api/reports`
- `GET /api/duplicates?product_id=...&version=...`
- `POST /api/members`、`POST /api/evidence`
- `POST /api/fixes`、`POST /api/extensions`
- `POST /api/reports/{id}/status`
- `POST /api/advisories`、`GET /api/reports/{id}/advisory?user_id=...`
- `POST /api/reports/{id}/publish`
- `GET /api/reports/{id}?user_id=...`
- `GET /api/reports/{id}/notifications`
- `POST /api/public-id-registrations`：协调员登记公开编号、预留到期日、公告地址
- `POST /api/public-id-registrations/{id}/renew`、`POST /api/public-id-registrations/{id}/withdraw`
- `GET /api/public-id-ledger?within_days=14`：全部登记、冲突编号、即将到期项和处理记录

状态流转限制为 `new -> triaged -> fixing -> resolved -> published`，拒绝或回到修复中也有显式规则。披露日期早于保密期限时请求会失败，不会只修改显示状态。

## 公开编号台账规则

- 同一公开编号在撤回前只能归一份报告（数据库部分唯一索引保证），由协调员登记编号、预留到期日和公告地址。
- 同一份报告重复登记同一编号：幂等返回已有登记；其他报告重复登记：返回 `409` 与持有报告信息，并写入冲突处理记录。
- 撤回登记后编号释放，可登记给其他报告；撤回记录保留。
- 续期必须晚于当前预留到期日并填写理由，事件中同时保留新旧期限。
- 预留到期未续期的报告不能披露（接口返回明确错误并记录 `publish_block` 事件），续期后放行；已公开报告不能再次披露或登记编号。
- 台账页面展示冲突编号、`within_days` 天内即将到期项和全部处理记录。
