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
