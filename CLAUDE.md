# CLAUDE.md

Edgeweir 边缘节点：Go agent（`edgeweir-node`）+ OpenResty/Lua 数据面。控制面在同级仓库 `../edgeweir`；契约（proto）变更先在控制面仓库提交并打 `proto/vX.Y.Z` tag，再在这里重新生成。架构见 ARCHITECTURE.md。

## 技术栈

- Go 1.27.1（`go.mod` 固定补丁版本，ADR-0017），模块 `github.com/marvinli001/edgeweir-node`，静态编译（`CGO_ENABLED=0`）
- 依赖只有 `connectrpc.com/connect` 和 `google.golang.org/protobuf`，其余用标准库（`log/slog`、`crypto/x509`、`flag`）
- 契约：`edgeweir/proto` 的 git tag（`PROTO_TAG`，当前 `proto/v0.4.0`），buf 生成到 `internal/gen/`（已提交，不要手改）
- 数据面：`openresty/openresty:1.31.1.1-bookworm`，Lua 模块在 `lua/edgeweir/`
- 发布：goreleaser v2（deb/rpm/tar.gz，linux amd64/arm64）、syft SBOM、cosign keyless、SLSA provenance

## 常用命令

```sh
go vet ./... && go test ./...        # 必须通过
make test-race lua-test e2e           # race、Lua（resty）、容器冒烟测试
COMPOSE_PROJECT_NAME=<名字> E2E_NODE_PORT=38080 E2E_PP_PORT=38081 E2E_HELPER_PORT=38090 make e2e
                                      # 与其他 compose 项目并行：项目名只隔开容器、网络和卷，宿主机端口（默认 28080/28081/28090）也要换
make proto / make proto-check         # 从 tag 重新生成 / 检查漂移
make adr-check                        # docs/adr 是否与 ../edgeweir 的 ADR 一致（需要同级检出，所以 CI 不跑）
go test ./internal/render -update     # 更新 nginx.conf golden 文件（review diff）
make docker && make snapshot          # 镜像、goreleaser 本地快照
```

## 约定

- Conventional Commits，小步提交；提交信息末尾带 `Co-Authored-By` 行（如适用）。
- 文档以中文为主，README 中英双语。
- `docs/adr/` 是控制台仓库 `docs/adr` 的镜像，由 `scripts/sync-adr.sh` 生成（只把指向控制台独有文件的相对链接换成 GitHub URL）。不要在这里编辑：ADR 先在控制台仓库修改，再运行 `scripts/sync-adr.sh` 同步；`scripts/sync-adr.sh --check`（`make adr-check`）检查镜像是否一致。
- 所有持久化写入用 `fsutil.WriteFileAtomic`。
- 写进 `nginx.conf` 的值必须先校验；站点等可变数据只走控制 socket，不进 `nginx.conf`。
- 改 content_hash 相关逻辑必须同步控制面，测试向量 `internal/configir/testdata/content_hash_vector*.json`（Phase 0、M2、v0.2.1）不能随意改。
- 站点、源站、规则 id 在数据面里是键的一部分，只接受 `[A-Za-z0-9_-]`；源站特殊地址段的列表在 `internal/configir/address.go` 和 `lua/edgeweir/ipaddr.lua` 各有一份，必须一致（控制台也按它校验）。
- Lua 里能写成纯函数的逻辑（地址判断、缓存键、错误分类）写成纯函数，由 `make lua-test` 覆盖；需要真实请求的行为放进 `test/e2e/run.sh`。

## 不可违反的原则

- 没有 phone-home、授权校验或默认开启的遥测。
- 节点私钥只在本机生成和保存（0600），从不传输；注册前必须按 `--ca-sha256` 固定 CA。
- 注册后所有 RPC 走 mTLS；控制 API 只监听 unix socket。
- 控制面不可达或新配置被拒绝时，继续按 last-known-good 配置服务。
- 不为让测试通过而跳过或削弱测试。
