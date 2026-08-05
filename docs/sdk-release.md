# foundation-sdk 发布流程

`foundation-sdk` 是业务侧（agent-platform 等）调用 SaaS Foundation 16 个微服务
的官方 Python 客户端。本文档说明如何打 wheel、推到内部 PyPI、回滚，以及
versioning 策略。

源代码：`sdks/python/foundation_sdk/`
构建脚本：`sdks/python/build.sh`、`sdks/python/publish.sh`
CI workflow：`.github/workflows/foundation-sdk-release.yml`
Makefile 入口：`make sdk-build` / `make sdk-publish-dry` / `make sdk-publish`

## 1. 版本号策略（semver）

| Bump  | 触发条件                                   | 消费侧动作                                  |
| ----- | ------------------------------------------ | ------------------------------------------- |
| patch | bugfix、性能优化、纯文档                   | 无需配合，下次 `poetry lock` 自动获取       |
| minor | 新增 resource、新增可选参数（向后兼容）    | 无需配合（pin 写作 `>=0.1,<0.2`）           |
| major | 删字段、改方法签名、改 wire-level 协议     | **必须**联动业务侧同 PR 升级，并发 ADR     |

业务侧 4 个服务的 pin 写法是 `foundation-sdk = ">=0.1,<0.2"` —— 这意味着所有
0.1.x、0.2.x 之内的发布自动滚到 lockfile。**major 升级必须开 ADR**，在
agent-platform 和 saas-foundation 双方都 merge 后才发布 `v1.0.0`，避免
"sdk 已发，但业务还没准备好" 的窗口。

## 2. 发布流程（正常路径）

1. 在 `sdks/python/pyproject.toml` bump `version`，提 PR。
2. PR merge 到 `main`，CI 自动跑 build job、把 wheel 作 artifact 上传（30 天保留）。
3. 在 `sdks/python/` 目录打 tag 触发 release：

   ```bash
   git tag foundation-sdk-v0.1.1 && git push origin foundation-sdk-v0.1.1
   ```

4. `foundation-sdk-release.yml` 的 `publish` job 进入 `internal-pypi`
   environment（如启用 protection rule 会先弹 approval），把 wheel 推到
   `${INTERNAL_PYPI_URL}`。
5. 验证：在干净环境执行
   `pip install --index-url $INTERNAL_PYPI_URL foundation-sdk==0.1.1`
   能成功 import 即 OK。

> Tag 名（去掉 `foundation-sdk-v` 前缀）会覆盖 pyproject 里的 version
> 写到 wheel，所以 tag 才是真正的 single source of truth。

## 3. 本地手动发布（应急）

```bash
export FOUNDATION_PYPI_URL=https://pypi.example.com/repository/pypi-hosted/
export FOUNDATION_PYPI_TOKEN=<token>
make sdk-publish-dry   # twine check，不上传
make sdk-publish       # 真上传
```

只有在 CI 不可用时才走这条路；同时务必在 git 上补 tag，保留审计链。

## 4. 回滚指南

内部 PyPI 一旦上传的版本号**禁止覆盖**（Nexus / devpi 默认 immutable）。
回滚 = 发新版：

1. 在 git 上 revert 引入 bug 的 commit；
2. bump 一个 patch 号（例如 `0.1.1` 出问题 -> 发 `0.1.2`，内容等同 `0.1.0`）；
3. 走正常发布流程；
4. 在业务侧执行 `poetry update foundation-sdk` 即可拉到 `0.1.2`。

如果发版本身坏到无法 import（极少见），可以**手动在内部 PyPI 上 yank 该版本**
（Nexus UI: "Delete"），这样所有 `>=0.1,<0.2` 的 solver 都会跳过这一版。
yank 后必须立即发补丁版。

## 5. 与 build-context 模式的关系

agent-platform 的 docker-compose 仍然保留
`additional_contexts: foundation_sdk` 作 dev 兜底（无网络 / SDK 改动还没发版
时使用）。两条路径的选择详见 `agent-platform/docs/foundation-sdk-consumption.md`。
