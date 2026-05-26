# Helm Umbrella Chart — `foundation`

> P0 #3.2 骨架版。当前没有真实 service 镜像，只渲染 Deployment 占位。
> service 实际成型后（P0 #4/#5 起），各 package 出独立 subchart，本目录的 `services-renderer.yaml` 弃用。

## 目录结构

```
deploy/helm/
├── foundation/                 # umbrella chart（你 helm install 的对象）
│   ├── Chart.yaml              # 含 9 个第三方组件 dependencies
│   ├── values.yaml             # 默认值（small profile 基线）
│   ├── values-small.yaml       # POC / 单节点 K3s / 50 用户
│   ├── values-medium.yaml      # 企业私有化 / 3-10 节点 / HA
│   ├── values-large.yaml       # 跨 AZ / 1000+ 用户 / SaaS 主集群
│   └── templates/
│       ├── NOTES.txt
│       ├── namespace-labels.yaml
│       └── services-renderer.yaml   # 18 个 service 批量渲染（临时方案）
└── _service-template/          # 给各 service 自己 subchart 复制的模板
    ├── Chart.yaml
    ├── values.yaml
    └── templates/
        ├── _helpers.tpl
        ├── serviceaccount.yaml
        ├── deployment.yaml
        ├── service.yaml
        ├── hpa.yaml
        ├── pdb.yaml
        └── networkpolicy.yaml
```

## 三档 profile 设计

| Profile | 节点 | HA | 第三方组件 | 副本 | 资源 | 适用 |
|---|---|---|---|---|---|---|
| **small** | 1-3 K3s | ❌ | 内嵌全开 | 1 | 8C/32G | POC、演示、50 用户 |
| **medium** | 3-10 K8s | ✅ | 外置或客户共享 | 3+，HPA | 32C/128G | 企业私有化 100-500 用户 |
| **large** | 20+ 跨 AZ | ✅+ | 全部外置 | 5+，HPA+Karpenter | 弹性 | 1000+ 用户 / SaaS 主集群 |

切换只需 `-f values-<profile>.yaml`，**chart 本体不变**。

## 快速开始（small profile，K3s 单节点）

```bash
# 1. 起 K3s（或现有 kubectl cluster）
curl -sfL https://get.k3s.io | sh -
sudo chmod 644 /etc/rancher/k3s/k3s.yaml
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# 2. 装 helm
brew install helm  # mac
# 或者 https://helm.sh/docs/intro/install/

# 3. 装 chart
cd deploy/helm/foundation
helm dependency update           # 拉第三方 subchart
helm install foundation . \
    -f values-small.yaml \
    -n foundation --create-namespace

# 4. 看进度
watch kubectl -n foundation get pods

# 5. 跑健康检查
helm test foundation -n foundation
```

## medium / large profile 注意事项

- **第三方组件外置**：默认 `enabled: false`，你需要在 secrets/values-prod.yaml 里填 `global.database.host` 等真实地址
- **凭据从 Vault / External Secrets 注入**：不要把密码写进 values.yaml，用 Secret 引用
- **mTLS**：`global.mtls.enabled=true`，需配套 cert-manager + 自签 CA
- **PgBouncer**：medium+ 务必走独立 PgBouncer Deployment（不要直连 Postgres），保持 transaction pool mode
- **存储类**：检查 `storageClassName` 与客户机房 CSI 匹配

## 升级与回滚

```bash
# 升级
helm upgrade foundation . -f values-small.yaml -n foundation

# 回滚到上一版
helm rollback foundation -n foundation

# 看历史
helm history foundation -n foundation
```

## 离线安装

`deploy/offline-bundle/` 会打包所有镜像 tar + helm chart + CRD（A-M5 交付）。

## 与 docker-compose 的关系

- docker-compose 用于**开发同学本地**起依赖；不部署 service
- helm 用于**部署 service 自身**（CI/staging/prod/客户机房）
- 两者底层组件版本应保持一致（Postgres 16、Keycloak 25、ClickHouse 24.8 等）

## 待办

- [ ] subchart：service 成型后每个 package 独立 helm subchart，本目录 services-renderer.yaml 删除
- [ ] CRD：sandbox-pool / tenant-router 等自研 Operator（B 阶段）
- [ ] cert-manager Issuer 模板
- [ ] ExternalSecret 模板（对接客户 Vault / AWS Secrets Manager）
- [ ] migration Job + Helm hook（pre-install / pre-upgrade）
- [ ] Backup CronJob（pgBackRest / Velero）
- [ ] 国密 OS / 鲲鹏镜像 multi-arch（v1.1）
