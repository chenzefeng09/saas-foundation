# saas-foundation

通用企业级 SaaS 平台底座。**独立产品、独立交付、可跨项目复用**。

提供身份 / 授权 / 组织 / 计费 / 审计 / 合规 / 通知 / 搜索 / API 平台 / LLM 网关等基础能力，业务系统通过 SDK 调用，不感知底层开源组件（Keycloak / OPA / ClickHouse / OpenSearch / LiteLLM 等）。

## 设计目标

- **私有化优先**：默认部署到客户机房，K8s 1.24+，离线安装
- **SaaS 兼容**：同一份 chart 切 profile 支持 SaaS 多租户多隔离档
- **合规一步到位**：v1.0 覆盖等保 2.0 三级 + PIPL；v1.1 国密 + 信创；v1.2 SOC2 + ISO 27001
- **可伸缩**：small / medium / large 三档 profile，HA + 弹性
- **业务零感知**：业务层 import SDK，不直接访问任何开源组件

## 仓库结构

```
saas-foundation/
├── packages/           # 各能力 service（identity / authz / org / billing / audit / ...）
├── sdks/               # 业务层 SDK（python / typescript / go）
├── contracts/          # OpenAPI 3.1 / gRPC proto / OPA bundle 模板
├── deploy/             # helm umbrella chart / docker-compose / 离线安装包
├── docs/
│   ├── design/         # 各 package 滚动细化设计文档
│   └── adr/            # 架构决策记录
└── tests/
    ├── e2e/            # 跨服务集成测试
    └── conformance/    # 业务接入自检套件
```

## 当前状态

✅ **P0 阶段（启动前细化）已交付**

- [x] P0 #1.1 CONVENTIONS.md
- [x] P0 #1.2 errors.md
- [x] P0 #1.3 OpenAPI 样例
- [x] P0 #1.4 Python SDK template
- [x] P0 #2 RLS 多租户基线
- [x] P0 #3 docker-compose / helm / CI/CD bootstrap
- [x] P0 #4 Identity 详细设计
- [x] P0 #5 Authz 详细设计

下一步：A-M1 启动后滚动细化 P1。

## 文档入口

**契约层**
- 架构总约定：[docs/CONVENTIONS.md](docs/CONVENTIONS.md)
- 错误码规范：[docs/errors.md](docs/errors.md)
- 多租户 RLS 基线：[docs/multi-tenancy.md](docs/multi-tenancy.md)
- 开发快速上手：[docs/dev-quickstart.md](docs/dev-quickstart.md)

**Service 设计**
- Identity v1：[docs/design/identity-v1.md](docs/design/identity-v1.md)
- Authz v1：[docs/design/authz-v1.md](docs/design/authz-v1.md)
- Org v1：[docs/design/org-v1.md](docs/design/org-v1.md)
- Crypto v1：[docs/design/crypto-v1.md](docs/design/crypto-v1.md)
- Auth Flows v1（密码/MFA/Session）：[docs/design/auth-flows-v1.md](docs/design/auth-flows-v1.md)

**部署**
- 本地开发栈：[deploy/docker-compose/README.md](deploy/docker-compose/README.md)
- Helm umbrella chart：[deploy/helm/README.md](deploy/helm/README.md)

**SDK 模板**
- Python：[sdks/python/_template/README.md](sdks/python/_template/README.md)

**ADR**（待第一份 ADR 产出后启用）
- `docs/adr/`
