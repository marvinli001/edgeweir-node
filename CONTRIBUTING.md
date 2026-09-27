# 参与贡献

欢迎参与 Edgeweir 边缘节点的开发。本仓库是节点侧：Go agent（`edgeweir-node`）加 OpenResty（Lua）。控制面在 [edgeweir/edgeweir](https://github.com/marvinli001/edgeweir)。

## 许可证

本项目使用 [AGPL-3.0-only](LICENSE)，允许合规商用。提交贡献即表示你同意你的贡献以 AGPL-3.0-only 授权，并确认有权这样做；不自动授予项目方闭源再许可权。开源核心与独立商业运营产品的范围见 [LICENSING.md](LICENSING.md) 和 [ADR-0019](docs/adr/0019-open-core-and-commercial-products.md)。

## 开始之前

- 新功能、新依赖、proto 变更等较大的改动，请先开 issue 讨论。
- 安全问题不要开公开 issue，请按 [SECURITY.md](SECURITY.md) 使用 GitHub 私密安全公告。

## 开发环境

| 工具 | 版本 | 用途 |
|---|---|---|
| Go | 1.27.1（`go.mod` 中为 `go 1.27.1`） | 构建、测试 |
| Docker | 近期版本 | 构建镜像、Lua 测试、e2e 冒烟测试 |
| buf | 1.73+ | 重新生成 proto 代码 |
| goreleaser | 2.x | 检查发布配置、本地构建快照 |
| syft | 近期版本 | goreleaser 生成 SBOM 时使用 |
| cosign | 可选 | 本地验证签名 |

## 常用命令

`make help` 列出所有目标。

| 命令 | 作用 |
|---|---|
| `make build` | 构建静态二进制到 `bin/edgeweir-node` |
| `make vet` | `go vet ./...` |
| `make test` | `go test ./...`，单元测试和进程内集成测试 |
| `make test-race` | 带 race detector 跑测试 |
| `make lua-test` | 在 OpenResty 镜像里用 `resty` 跑 Lua 单元测试 |
| `make docker` | 构建节点容器镜像 |
| `make e2e` | 容器冒烟测试（假控制面 + 节点 + 源站） |
| `make proto` | 从 proto git tag 重新生成 Go 代码 |
| `make proto-check` | 重新生成，若与已提交的代码不一致则失败 |
| `make pin-check` | 第三方镜像没按 digest、GitHub Actions 没按 commit SHA 固定时失败（`scripts/check-pins.sh`，CI 运行） |
| `make adr-check` | `docs/adr` 与同级目录 `../edgeweir` 的 ADR 不一致时失败（`scripts/sync-adr.sh --check`；CI 没有同级检出，不运行它） |
| `make release-check` | 校验 goreleaser 配置 |
| `make snapshot` | 本地构建发布物，不发布，不签名 |

提 PR 前，`go vet ./...` 和 `go test ./...` 必须通过。另外：

- 改了 Lua：跑 `make lua-test`
- 改了渲染、数据面或镜像：跑 `make e2e`
- 改了 goreleaser 配置：跑 `make release-check`
- 改了 Dockerfile、compose、Makefile 的镜像或工作流：跑 `make pin-check`（见下方「更新固定的镜像与 Actions」）
- 同步了 ADR（`docs/adr` 是控制面仓库 ADR 的镜像，先在那里修改，再运行 `scripts/sync-adr.sh`）：跑 `make adr-check`

## 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/)：

```
<type>(<scope>): <简短描述>
```

- type：`feat`、`fix`、`docs`、`test`、`build`、`ci`、`chore`、`refactor`、`perf`
- scope 示例：`enroll`、`agent`、`configir`、`render`、`dataplane`、`engine`、`lua`、`proto`
- 破坏性变更在 type 后加 `!`，或在正文写 `BREAKING CHANGE:`

示例：

```
feat(render): render resolver block from NodeConfig
fix(enroll): reject CA that does not match the pinned sha256
feat(proto): bump contract to proto/v0.1.1
```

推荐用 `git commit -s` 加上 `Signed-off-by`（DCO），但不强制。

## 更新固定的镜像与 Actions

第三方镜像按 `tag@sha256:<digest>`、GitHub Actions 按 `owner/action@<40 位 SHA> # vX.Y.Z` 引用（ADR-0017），`make pin-check` 拒绝未固定的写法；本仓库自己构建的 `edgeweir-node:*` 镜像除外。升级时 tag 与 digest（或 SHA 与版本注释）一起改：

- 镜像：`docker buildx imagetools inspect <镜像>:<tag>` 输出的 `Digest` 就是多架构 index 的 digest（不要用单一平台的 digest）。
- Actions：`git ls-remote --tags https://github.com/<owner>/<action>` 找到版本 tag 对应的提交；带 `^{}` 的行是附注 tag 指向的提交，要用这一行的 SHA。

## Proto 契约与代码生成

节点和控制面之间唯一的契约是 protobuf，放在 `edgeweir/edgeweir` 仓库的 `proto/` 目录，以 git tag `proto/vX.Y.Z` 发布。本仓库从不复制 `.proto` 文件，生成的代码放在 `internal/gen/` 并提交到仓库。

升级到新的契约版本：

1. 在 `Makefile` 里把 `PROTO_TAG` 改成新 tag，例如 `proto/v0.1.1`。
2. 运行 `make proto`。默认输入是同级目录的检出：`../edgeweir/.git#tag=$(PROTO_TAG),subdir=proto`，需要先 `git -C ../edgeweir fetch --tags`。
3. 把 `internal/gen/` 和相关代码改动放在同一个 `feat(proto): ...` 提交里。

CI 会运行：

```bash
make proto-check PROTO_INPUT='https://github.com/marvinli001/edgeweir.git#tag=<tag>,subdir=proto'
```

如果已提交的生成代码过期，CI 失败。

生成器版本通过 `go.mod` 里的 `tool` 指令固定（`protoc-gen-go`、`protoc-gen-connect-go`），`buf.gen.yaml` 用 `go tool` 调用它们，所以生成器版本始终与运行时库一致。

## 测试

- 单元测试放在被测代码旁边。
- golden 文件（例如 `internal/render/testdata` 里的 `nginx.conf`）用 `go test ./internal/render -update` 重新生成，并在 diff 里逐行检查变化。
- `internal/configir/testdata/content_hash_vector.json` 是与控制面共享的内容哈希测试向量。除非控制面同步做了对应修改，否则不能改动。
- 不要跳过或削弱测试来让 CI 通过。

## 不可违反的原则

- 没有 phone-home，遥测默认关闭，没有授权或许可证校验。
- 节点私钥从不离开节点。
- 第三方依赖保持最少，目前只有 connect-go 和 protobuf-go。引入新依赖前先开 issue 讨论。
- `edgeweir/proto` 是两个仓库之间唯一的契约，不要绕过它私下约定格式。
- 安全问题通过 GitHub 私密安全公告报告，不开公开 issue，见 [SECURITY.md](SECURITY.md)。

## Pull Request

- 一个 PR 只做一件事，按逻辑拆成小提交。
- 描述里写清动机、改动内容和验证方式。
- CI 全部通过后再请求 review。
