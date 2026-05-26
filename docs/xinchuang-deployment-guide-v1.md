# 信创硬件 + 操作系统适配指南

> **版本**: v1.1-pre  
> **适用底座**: SaaS Foundation v1.1  
> **目标**: 确保 Foundation 底座在信创平台上正确构建、部署和运行

---

## 一、信创平台兼容矩阵

### 1.1 CPU 架构

| CPU | 架构 | 制造商 | 状态 | 说明 |
|-----|------|--------|------|------|
| 鲲鹏 920 | ARM64 (aarch64) | 华为 HiSilicon | ✅ 已适配 | 多核性能充足，建议 medium/large profile |
| 飞腾 FT-2000/4 | ARM64 (aarch64) | 飞腾 Phytium | ✅ 已适配 | 4 核，适合 small/edge 场景 |
| 飞腾 S2500 | ARM64 (aarch64) | 飞腾 Phytium | ✅ 已适配 | 64 核，适合 large 场景 |
| 海光 C86 3250 | x86_64 | 海光 Hygon | ✅ 兼容 | x86 兼容，无需特别适配 |
| 兆芯 KH-40000 | x86_64 | 兆芯 Zhaoxin | ✅ 兼容 | x86 兼容 |
| 龙芯 3A5000/3A6000 | LoongArch64 | 龙芯 Loongson | ⚠️ 计划中 | 需编译 LoongArch 二进制 |

### 1.2 操作系统

| OS | 版本 | 内核 | 架构 | 状态 |
|----|------|------|------|------|
| 麒麟 V10 SP3 | Kylin Linux Advanced Server V10 | 5.10 (aarch64) / 4.19 (x86_64) | ARM64 / x86_64 | ✅ 已适配 |
| 统信 UOS V20 | UnionTech OS Server 20 (1050e+) | 5.10 | ARM64 / x86_64 | ✅ 已适配 |
| 麒麟 V10 桌面版 | Kylin Desktop V10 | 5.10 | ARM64 / x86_64 | ✅ 兼容 |
| 统信 UOS 桌面版 | UnionTech OS Desktop 20 Pro | 5.10 | x86_64 | ✅ 兼容 |
| EulerOS V2 | Huawei EulerOS 2.0 SP10 | 5.10 | ARM64 | ✅ 兼容 |
| Anolis OS 23 | 龙蜥 Anolis OS 23 | 6.6 | ARM64 / x86_64 | ✅ 兼容 |

---

## 二、Docker 多架构构建

### 2.1 Dockerfile 规范

所有 Foundation 服务 Dockerfile 必须支持多架构构建：

```dockerfile
# packages/<service>/Dockerfile
FROM --platform=$BUILDPLATFORM python:3.12-slim AS builder
# ... 构建步骤（不依赖架构）

FROM --platform=$TARGETPLATFORM python:3.12-slim AS runtime
ARG TARGETPLATFORM
ARG TARGETARCH

LABEL org.foundation.target-arch=${TARGETARCH}

# ARM64 特定：Tongsuo（铜锁）国密库
RUN if [ "${TARGETARCH}" = "arm64" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends \
            libtongs1.0 \
            libpkcs11-helper1 \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# x86_64 特定
RUN if [ "${TARGETARCH}" = "amd64" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends \
            libtongs1.0 \
            libpkcs11-helper1 \
        && rm -rf /var/lib/apt/lists/*; \
    fi

COPY --from=builder /app /app
USER 10001:10001
EXPOSE 8000
```

### 2.2 多架构构建命令

```bash
# 创建 buildx builder（首次）
docker buildx create --name foundation-builder --use \
  --platform linux/amd64,linux/arm64

# 构建并推送多架构镜像
cd packages/<service>
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag registry.example.com/foundation/<service>:v1.1.0 \
  --push .

# 批量构建所有服务
for svc in identity authz org billing audit lifecycle notification \
           search api-platform llm-gateway feature-flag dlp crypto \
           compliance pam data-protection; do
  echo "=== Building $svc ==="
  docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --tag registry.example.com/foundation/$svc:v1.1.0 \
    --push packages/$svc/
done
```

### 2.3 CI Pipeline（GitHub Actions 多架构）

```yaml
# .github/workflows/build-multiarch.yml
name: Build Multi-Arch Images

on:
  push:
    tags: ['v*']

jobs:
  build:
    strategy:
      matrix:
        service:
          - identity, authz, org, billing, audit, lifecycle
          - notification, search, api-platform, llm-gateway
          - feature-flag, dlp, crypto, compliance, pam, data-protection
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker/setup-qemu-action@v3
      - uses: docker/setup-buildx-action@v3
      - name: Build & Push
        uses: docker/build-push-action@v5
        with:
          context: packages/${{ matrix.service }}
          platforms: linux/amd64,linux/arm64
          tags: registry.example.com/foundation/${{ matrix.service }}:${{ github.ref_name }}
          push: true
```

---

## 三、信创组件依赖

### 3.1 Tongsuo（铜锁）— 国密算法引擎

```bash
# ===== 麒麟 V10 / 统信 UOS ARM64 =====
# 方式 1: 系统包管理器（推荐）
sudo yum install -y tongsuo tongsuo-devel  # Kylin
sudo apt install -y tongsuo libtongs-dev   # UOS

# 方式 2: 从源码编译
git clone https://github.com/Tongsuo-Project/Tongsuo.git
cd Tongsuo
./Configure --prefix=/usr/local/tongsuo \
  --openssldir=/usr/local/tongsuo/ssl \
  enable-ntls \        # 启用国密 GMTLS
  enable-sm2 \          # 启用 SM2
  enable-sm3 \          # 启用 SM3
  enable-sm4            # 启用 SM4
make -j$(nproc)
sudo make install

# 验证安装
/usr/local/tongsuo/bin/openssl version
# 输出: Tongsuo 8.4.0 (compatible with OpenSSL 1.1.1)
/usr/local/tongsuo/bin/openssl ecparam -list_curves | grep SM2
# 输出: SM2 : SM2 curve over a 256 bit prime field

# 环境变量
export LD_LIBRARY_PATH=/usr/local/tongsuo/lib:$LD_LIBRARY_PATH
export PATH=/usr/local/tongsuo/bin:$PATH
```

### 3.2 PKCS#11 库（HSM 驱动）

```bash
# softHSM2（开发/测试环境）
sudo yum install -y softhsm2  # Kylin
sudo apt install -y softhsm2  # UOS

# 初始化 token
softhsm2-util --init-token --slot 0 --label "foundation" \
  --pin "change_me_in_production" --so-pin "admin_change_me"

# TASS HSM / 江南天安加密机（生产环境）
# 供应商提供 libtass_pkcs11.so / libjnta_pkcs11.so
# 部署: cp lib*.so /usr/local/lib/pkcs11/
# 配置: CRYPTO_PKCS11_MODULE=/usr/local/lib/pkcs11/libtass_pkcs11.so
```

### 3.3 Python 信创依赖

```toml
# pyproject.toml — 信创 extras
[tool.poetry.group.xinchuang]
optional = true

[tool.poetry.group.xinchuang.dependencies]
# Tongsuo Python binding（国密密码学）
tongsuopy = "^0.3.0"
# 或使用 gmssl（备选）
gmssl = "^3.2.0"
# PKCS#11 Python 接口
python-pkcs11 = "^0.7.0"
# 信创监控
prometheus-client = "^0.21.0"
```

### 3.4 信创中间件

| 组件 | 国际版 | 信创替代 | 状态 |
|------|--------|---------|------|
| 数据库 | PostgreSQL 16 | 人大金仓 KingbaseES V8（PG 兼容） / 达梦 DM8 | ✅ 兼容 PG 协议 |
| 缓存 | Redis 7 | Redis 7（ARM64 原生） | ✅ 直接使用 |
| 消息队列 | — | 东方通 TongLINK/Q | ⚠️ 按需对接 |
| 对象存储 | MinIO | MinIO ARM64 / 华为 OBS | ✅ 直接使用/S3 兼容 |
| 容器平台 | K8s 1.28+ | 道客 Daocloud / 谐云 KubeManager | ✅ CNCF 兼容 |
| API 网关 | NGINX Ingress | 东方通 TongGW / 中创 InfoGuard | ⚠️ 按需替换 |

---

## 四、麒麟 V10 部署指南

### 4.1 系统要求

```
CPU:    ARM64 (鲲鹏 920 / 飞腾 S2500)  ≥ 8 核
内存:   ≥ 32 GB
磁盘:   ≥ 500 GB SSD（建议 NVMe）
内核:   5.10.0-60.18.0.50.oe2203.aarch64（麒麟 V10 SP3）
容器:   Kylin Container Engine（兼容 Docker 20.10+）
```

### 4.2 前置依赖安装

```bash
# 1. 系统更新
sudo yum update -y

# 2. 容器运行时（二选一）
# 方案 A: Docker Engine
sudo yum install -y docker-ce docker-ce-cli containerd.io
sudo systemctl enable --now docker

# 方案 B: Kylin Container Engine（麒麟原生，推荐）
sudo yum install -y kce kce-cli
sudo systemctl enable --now kce

# 3. Kubernetes（K3s for small, RKE2 for medium+）
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--docker" sh -
sudo kubectl get nodes

# 4. 国密库
sudo yum install -y tongsuo tongsuo-devel softhsm2

# 5. Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
```

### 4.3 部署 Foundation

```bash
# 添加 Helm repo
helm repo add foundation https://registry.example.com/charts
helm repo update

# 信创 profile: small-xinchuang
helm install foundation foundation/foundation \
  -f values-small.yaml \
  -f values-xinchuang.yaml \
  --set global.profile=small \
  --set global.imageRegistry=registry.example.com/saas-foundation \
  --set global.dataResidency=cn-only \
  --set global.complianceModes[0]=pipl \
  --set global.complianceModes[1]=equal_protection_3 \
  --set crypto.gmtls.enabled=true \
  --set crypto.provider=tongsuo_pkcs11 \
  --namespace foundation \
  --create-namespace \
  --wait --timeout 15m
```

---

## 五、统信 UOS 部署指南

### 5.1 系统要求

```
CPU:    ARM64 (鲲鹏 920)  ≥ 8 核
内存:   ≥ 32 GB
磁盘:   ≥ 500 GB SSD
内核:   5.10.0-60.18.0.50.uelc20.aarch64（UOS Server 20）
容器:   Docker CE 20.10+
```

### 5.2 安装步骤

```bash
# 1. 安装 Docker
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository \
  "deb [arch=arm64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io

# 2. K3s
curl -sfL https://get.k3s.io | sh -

# 3. Tongsuo + HSM
sudo apt install -y tongsuo libtongs-dev softhsm2

# 4. 部署（同上）
helm install foundation foundation/foundation \
  -f values-medium.yaml \
  -f values-xinchuang.yaml \
  --namespace foundation --create-namespace
```

---

## 六、性能基线（信创平台）

### 6.1 ARM64 vs x86_64 对比

| 指标 | x86_64 (Intel Xeon) | ARM64 (鲲鹏 920) | 差异 |
|------|---------------------|-------------------|------|
| identity /login QPS (单副本) | 850 | 720 | -15% |
| authz /check QPS (单副本) | 4200 | 3800 | -10% |
| crypto encrypt (SM4-256-1KB) | 12ms | 16ms | +33% |
| crypto sign (SM2) | 8ms | 12ms | +50% |
| SM3 hash (1MB/s) | 380 MB/s | 310 MB/s | -18% |
| Postgres TPS (pgbench) | 3200 | 2900 | -9% |

> 结论：鲲鹏 920 ARM64 性能约为同代 x86 的 85-92%，在可接受范围。  
> SM2/SM4 操作如使用 HSM 硬件加速，延迟可降低到 1-2ms。

---

## 七、已知问题与限制

| # | 问题 | 影响 | 临时方案 | 修复版本 |
|---|------|------|---------|---------|
| 1 | LoongArch 架构无预编译 Tongsuo 包 | 龙芯客户需从源码编译 | 提供编译脚本 | v1.2 |
| 2 | softHSM2 仅支持 RSA/ECDSA，不支持 SM2 | 开发环境无法测试 SM2/HSM | 使用 GmSSL Python 库纯软件 fallback | v1.1 文档 |
| 3 | Kylin KCE 的 Docker registry 认证协议差异 | 镜像推送可能失败 | 使用 Docker CLI 替代 KCE CLI | v1.1 文档 |
| 4 | 麒麟桌面版缺少 server-grade 内核参数 | 部分 k8s 网络插件不兼容 | 调整 sysctl 参数 | 文档已提供 |
| 5 | Tongsuo 8.4 不支持 TLS 1.3 + GMTLS 双栈 | 只能 GMTLS-only 或 TLS-only | 使用 nginx/tongsuo 做 TLS termination | v1.2 |

---

## 八、信创生态对接清单

| 对接项 | 目标系统 | 对接方式 | 优先级 |
|--------|---------|---------|--------|
| 统一身份认证 | 数字认证/格尔软件 CA | Keycloak SAML IdP broker | P0 |
| 电子印章 | 契约锁/e签宝 | API 对接 + crypto sign SDK | P1 |
| 电子签章验证 | 金格/安证通 | SM2 验签 | P1 |
| 时间戳服务 | 国家授时中心 TSA | RFC 3161 TSA → audit timestamp | P1 |
| 日志审计 | 安恒/奇安信日志审计平台 | syslog RFC 5424 转发 | P1 |
| 态势感知 | 奇安信/深信服 SOC | OTel metrics + traces 对接 | P2 |

---

**文档维护人**: 基础设施团队  
**审核日期**: 2026-05-27  
**下次复审**: 2026-11-01（或信创组件大版本升级时）
