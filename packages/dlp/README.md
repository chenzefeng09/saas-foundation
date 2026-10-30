# foundation-dlp

> SaaS Foundation 数据防泄露服务：资源分级、DLP 规则与检查事件。

## 访问级别信任链

- `POST /api/dlp/v1/core/check:read` 只接收 `resource_type`、`resource_id`。
- `POST /api/dlp/v1/core/check:download` 只接收 `resource_type`、`resource_id`、`destination`。
- 用户 ID 必须来自可信 `X-User-Id` 请求上下文；用户密级由 DLP 服务调用 Identity
  `GET /api/identity/v1/users/{user_id}` 获取。Identity 不可用或返回非法密级时检查失败闭合。
- 资源未标记时默认按 L3 处理，`DLP_UNCLASSIFIED_SENSITIVITY` 只能收紧为 L4/L5；Identity 地址和
  超时分别由 `DLP_IDENTITY_URL`、`DLP_IDENTITY_TIMEOUT_SECONDS` 配置。
- 资源标记、文件分类和敏感词管理仅允许可信 `SERVICE` / `ADMIN` actor。
- `POST /api/dlp/v1/core/scan` 对任何带租户上下文（`X-Tenant-Id`）的调用方开放：返回
  `{hits, max_sensitivity, action}`，命中一律记 DLP 事件。只有可信 `SERVICE` / `ADMIN` 调用
  才会把命中的最高级别写入/升级为该资源的分级标签；其他 actor（例如经 tool-broker 扫描自身
  工具调用的沙箱 worker）只拿判定、不改标签，否则不可信调用方可以抬高任意资源的标签。
