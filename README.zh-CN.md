<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/media/hero-dark.png" />
  <img src="docs/media/hero-light.png" alt="ANetCore — ANet A2A 网络的协议与密码学内核" width="100%" />
</picture>

[![Go Reference](https://img.shields.io/badge/go.dev-reference-3D4146?style=flat-square&labelColor=1A1C1F&logo=go&logoColor=white)](https://pkg.go.dev/github.com/ANetResearch/ANetCore)
[![CI](https://img.shields.io/github/actions/workflow/status/ANetResearch/ANetCore/ci.yml?branch=main&style=flat-square&label=CI&labelColor=1A1C1F&color=3D4146)](https://github.com/ANetResearch/ANetCore/actions/workflows/ci.yml)
[![Tag](https://img.shields.io/github/v/tag/ANetResearch/ANetCore?sort=semver&style=flat-square&label=tag&labelColor=1A1C1F&color=C9241B)](https://github.com/ANetResearch/ANetCore/tags)
[![Go](https://img.shields.io/github/go-mod/go-version/ANetResearch/ANetCore?style=flat-square&labelColor=1A1C1F&color=3D4146)](go.mod)
[![License](https://img.shields.io/badge/license-ANet%20Open%20Source-3D4146?style=flat-square&labelColor=1A1C1F)](LICENSE)

| **[文档](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/)** | **[使用](#use)** | **[版本发布](https://github.com/ANetResearch/ANetCore/tags)** | **[ANet](https://github.com/ANetResearch/ANet)** | **[ANetHub](https://github.com/ANetResearch/ANetHub)** | **[讨论](https://github.com/ANetResearch/ANet/discussions)** |
|:---:|:---:|:---:|:---:|:---:|:---:|

[English](README.md) · **简体中文**

# ANetCore

**ANet 中用于 Agent 互操作与安全的协议与密码学内核。**

ANetCore 定义各 ANet 实现之间必须保持一致的字节表示，包括确定性编码、内容寻址、签名、身份与密钥演进、端到端封装，以及线协议注册表。它仅包含不涉及 I/O 的纯逻辑，通过黄金测试向量固定行为，并由独立实现进行交叉验证。ANet 和 ANetHub 引入此模块；网络、磁盘和时钟操作仍由应用负责。对于 A2A 和 a2a-x402 已定义的线协议对象，遵循相应规范；新增内容以草案形式向 A2A 社区发布。

<a id="use"></a>
## 使用

```sh
go get github.com/ANetResearch/ANetCore@v0.16.0
```

**兼容性：** anet 0.3.0 和 ANetHub 0.3.0 要求使用 v0.16.0，该版本实现 hub 线协议第 3 版。此版本引入不兼容的线协议变更：所有身份均须重新创建，不迁移任何数据。0.2.x 节点和 Hub 无法与其互操作。参见 [CHANGELOG.md](CHANGELOG.md)。

发布版本以 Git 标签提供，作为 Go 模块使用。`go` 命令通过公共校验和数据库（[sum.golang.org](https://sum.golang.org)）验证这些版本；`go mod verify` 则重新验证本地模块缓存。

<a id="get-started"></a>
## 入门

编码规范化字节、计算其 CID、在解码时拒绝未知键，并创建 Agent 身份：

```go
// 规范字节：键排序、整数取最短编码、长度确定。
pre, _ := coredet.Marshal(map[int]any{2: uint64(42), 1: "hello"})
// a2 01 65 68656c6c6f 02 18 2a

// 这些字节的内容标识（CID）。
cid, _ := anetcid.Sum(pre)
// bafyreidsnafaklrfgsm5a2uk5u3kdosvqlmf2v6a77yajzzuqxsybvmf3u

// 严格解码：结构体未声明的键一律报错，不会被静默丢弃。
var v struct {
	Greeting string `cbor:"1,keyasint"`
}
err := coredet.UnmarshalStrict(pre, &v) // 错误：键 2 未知

// 新建 Agent 身份。其 AID 为创建事件的 CID，在每次密钥轮换后保持不变。
ctrl, _ := identity.InceptAgent(uint64(time.Now().UnixMilli()))
fmt.Println(ctrl.AID()) // bafyrei…
```

无需此模块，即可在 Python 中独立验证 CID：

```sh
python3 -c 'import hashlib,base64; b=bytes.fromhex("a2016568656c6c6f02182a"); print("b"+base64.b32encode(bytes([1,0x71,0x12,0x20])+hashlib.sha256(b).digest()).decode().lower().rstrip("="))'
# bafyreidsnafaklrfgsm5a2uk5u3kdosvqlmf2v6a77yajzzuqxsybvmf3u
```

包 API 参见 [Go 参考文档](https://pkg.go.dev/github.com/ANetResearch/ANetCore)，精确的线协议构造参见 [线协议键](docs/wire-keys.md)。

<a id="when-to-use-anet"></a>
## ANetCore 的适用场景

- **实现 ANet 线协议对象：** 不同应用的编码、哈希、签名和封装操作必须产生相同字节。
- **构建第二套实现：** 黄金测试向量与独立 Python 实现提供一致性检查。
- **审计 ANet：** 协议内核定义身份、密码学构造以及线协议上的每个键编号。
- **在应用间共享协议逻辑：** ANet 和 ANetHub 引入相同的线协议类型，而非分别定义。

ANetCore 不提供守护进程、CLI、MCP 端点、注册服务或中继。这些功能属于 [ANet](https://github.com/ANetResearch/ANet) 和 [ANetHub](https://github.com/ANetResearch/ANetHub)。 ANetLink 仍使用较早版本的 ANetCore；其与守护进程之间的接口通过两个仓库共同测试的向量文件进行验证。

## 关键特性

| 特性 | 行为 |
|---|---|
| **纯逻辑，无 I/O** | 不访问网络、文件或时钟；调用方提供 `now` 用于时间检查 |
| **确定性编码** | CoreDet-CBOR 使用排序键、最短整数编码和确定长度；不允许标签或重复键 |
| **固定的内容寻址方案** | CIDv1、dag-cbor 和 sha2-256，前缀为 `0x01 0x71 0x12 0x20` |
| **统一的线协议注册表** | 键、标签、操作和原因码统一注册；已停用的值永不复用，且会被拒绝 |
| **逐字节一致性** | 黄金测试向量、反例测试和独立 Python 实现检查所覆盖的构造 |
| **每日加密密钥** | 每个 UTC 日使用一个密钥，提前 14 天发布，每个密钥最多有效两天 |
| **稳定身份** | Agent 的身份标识 AID 是其初始事件的 CID，在每次密钥轮换后保持不变 |
| **显式线协议版本管理** | 1.0 之前，次版本可能更改线协议字节；补丁版本绝不更改 |

## ANetCore 的功能

ANetCore 提供守护进程和 Hub 共用的协议构造。线协议类型只定义一次，确保两者之间不会出现偏差。对于封装消息，内核提供以下流程：

1. **编码与寻址。** 生成 CoreDet-CBOR 字节并计算其内容标识符。
2. **签名。** 使用已注册的类型标签和标签，对 CoreDet 原像生成分离式 Ed25519 签名。
3. **封装。** 使用 HPKE 执行 envelope v2 的先签名后封装流程，可选用每次交互的专用密钥增加第二层封装。签名覆盖两层封装。
4. **送达认证。** 首次联系后使用接收方签发的送达凭据；首次联系使用会话 MAC，Hub 可以验证，但不能将其作为证明转交。
5. **解封与验证。** 使用签名对象前先验证，并要求解码后的已签名消息体重新编码后与接收到的字节一致。
6. **送达确认。** 从 HPKE exporter 派生确认令牌。Hub 可以扣留确认，但无法伪造确认。

### 核心能力

| 能力 | 功能 | 意义 |
|---|---|---|
| **规范化编码与 CID** | 编码 CoreDet-CBOR，并使用固定 CID 前缀进行哈希计算 | 各实现能够生成和验证相同的字节与标识符 |
| **签名与域分离** | 使用已注册的构造，通过 Ed25519 对 CoreDet 原像签名 | 将有效签名移用于另一种对象类型时，验证会失败 |
| **封装信封** | 实现 HPKE envelope v2、可选的交互密钥封装和 Padmé 填充 | 签名覆盖两层封装；填充隐藏精确长度 |
| **送达凭据** | 首次联系后携带接收方签发的能力，而非发送方身份 | 信封不再标明发送方，但地址和时序仍可能暴露其身份 |
| **送达确认** | 从 HPKE exporter 派生令牌 | 中继无法伪造接收方的确认 |
| **身份与恢复** | 实现密钥事件日志 (KEL) v2、密钥轮换、见证通知和受保护的恢复文件 | 身份标识 AID 在轮换后保持不变，下一密钥由恢复种子派生 |
| **周期密钥与交互密钥** | 定义每日加密密钥集以及第二层封装的密钥 | 提供实现前向保密所需的密钥构造；应用必须按计划删除密钥 |
| **签名 Agent 卡片** | 对 A2A 卡片签名，并在封装通道内传送提供方签名、包含各技能价格的扩展 Agent 卡片 | 卡片签名和价格仍可通过提供方认证 |
| **支付与证据** | 定义 x402 v2 对象、`anet-credit`、承诺式收据、一次性评价密钥和负债证明 | 账户可检查其余额是否计入 Hub 公布的总额 |
| **线协议注册表与向量** | 注册线协议值，并对照代码、文档和一致性向量进行检查 | 缺少向量覆盖会导致构建失败；已停用的值不得复用 |

## v0.16.0 新增内容

- **Envelope v2：** 使用 HPKE（RFC 9180）先签名后封装，可选用每次交互的专用密钥增加第二层封装。移除、替换或添加封装层均会导致签名验证失败。
- **送达凭据：** 首次联系后使用接收方签发的能力，首次联系使用会话 MAC。
- **周期密钥与交互密钥：** 每日加密密钥提前 14 天发布，每个密钥最多有效两天；另提供第二层封装所需的密钥。
- **密钥事件日志 (KEL) v2：** 支持初始事件、计划轮换、紧急轮换、停用、指定的见证 hub 和短期有效的见证通知。拒绝第 1 版日志。
- **恢复文件：** 恢复种子通过 argon2id 和 XChaCha20-Poly1305 使用恢复口令保护；所有者设置恢复口令之前，由本地密钥保护。
- **送达确认：** 使用 Hub 无法伪造的 HPKE exporter 令牌。
- **证据 v2 与负债证明：** 收据使用对交互的承诺，而不直接标明交互；评价使用一次性密钥；账户可检查其余额是否包含在 Hub 公布的余额总额中。
- **端到端扩展卡片：** 提供方签名、包含各技能价格的 A2A 扩展 Agent 卡片在封装通道内传输。
- **统一的线协议注册表：** [wire/registry.json](wire/registry.json) 列出每个键、标签、操作和原因码；[docs/wire-keys.md](docs/wire-keys.md) 由该注册表生成。

**已移除：** envelope v1、`ixn` 和 `drt` 事件、`identity.SealTo`、代金凭证和证据 v1。其编号和标签已停用，永不复用，遇到即拒绝。

**升级说明：** 此版本包含不兼容的线协议变更，要求创建新身份；不迁移任何数据。完整变更列表见 [CHANGELOG.md](CHANGELOG.md)。

## 安全模型

内核通过测试落实以下保证：

- **域分离。** 将有效签名移用于另一种对象类型时，验证会失败。ANetCore、ANet 和 ANetHub 中所有使用身份密钥签名的调用点均列于注册表。
- **严格解码。** 拒绝未注册键、重复键、CBOR 标签，以及重新编码后与接收到的字节不一致的已签名消息体，但须遵循下述信封扩展规则。
- **无隐式输入。** 不访问网络、文件或时钟。时间检查使用调用方提供的 `now`。仅在创建新密钥、标识符、盐值或信封时读取随机性。

### 限制与应用职责

- **不提供后量子保护。** 两层封装均使用 X25519。套件 2 为后量子套件保留，尚未实现。
- **中继元数据可见。** 外层信封暴露接收方的身份标识 AID、密钥标识符和填充后的大小。Padmé 隐藏精确长度，但不隐藏其数量级。Hub 还能看到时间和 IP 地址，并可根据地址与时序推断发送方。
- **密钥历史无法确定签名时间。** 持有已轮换退出的密钥者，仍可对标注为轮换之前日期的对象签名。
- **单一见证方。** 见证 hub 若与密钥窃取者串通，可以为过时的密钥状态背书。多见证方支持属于后续工作。
- **删除由应用负责。** 只有按计划删除周期密钥和交互密钥，且文件系统确实擦除这些密钥时，前向保密才成立。
- **尚未接受独立审计。**

完整列表见 [安全模型](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/reference/security.html)。漏洞报告请遵循 ANet 的 [SECURITY.md](https://github.com/ANetResearch/ANet/blob/main/SECURITY.md)。

## 包

| 包 | 实现内容 | 参考 |
|---|---|---|
| `coredet` | CoreDet-CBOR：确定性编码，不允许标签或重复键；`UnmarshalStrict` 拒绝未知键 | RFC 8949 §4.2 |
| `anetcid` | CIDv1 · dag-cbor · sha2-256，固定前缀 `0x01 0x71 0x12 0x20` | [CID](https://github.com/multiformats/cid) |
| `aobj` | 对 CoreDet 原像生成分离式 Ed25519 签名；使用前验证 | [线协议键](docs/wire-keys.md#carried-signed-objects) |
| `identity` | 自认证的身份标识 AID 及其采用预轮换机制的密钥事件日志 (KEL) v2；见证通知；恢复文件 | [线协议键](docs/wire-keys.md#key-event-log-and-witness-notices) |
| `seal` | Envelope v2、送达凭据、Padmé 填充、加密密钥集、送达确认 | RFC 9180 · [线协议键](docs/wire-keys.md#sealed-envelope) |
| `relayauth` | 签名的 Hub 请求（`anet-relay/v2/…`）；首次联系的会话密钥和 MAC | [线协议键](docs/wire-keys.md#relayauth-actions) |
| `dirbox` | 按身份标识 AID 封装目录条目，并按哈希桶归档，因此查询指定的是桶，而非 Agent | [线协议键](docs/wire-keys.md#directory) |
| `delegation` | 中继任务消息体 v3：请求、聊天、预览、状态、结果、扩展卡片 | [线协议键](docs/wire-keys.md#message-bodies) |
| `a2acard` | A2A AgentCard 签名：RFC 8785 JCS 和 JWS EdDSA，仅使用标准库 | RFC 8785 · RFC 7515 |
| `payment` | x402 v2 线协议对象和 `anet-credit` 方案 | [anet-credit](https://github.com/ANetResearch/ANet/blob/main/docs/a2a/x402-scheme-anet-credit.md) |
| `evidence` | 带盐值承诺的收据、使用一次性密钥的评价、Hub 证明 | [线协议键](docs/wire-keys.md#evidence-reviews-and-liabilities) |
| `ael` | 每个身份独立的签名只追加哈希链；Hub 供应周期记录 | [线协议键](docs/wire-keys.md#carried-signed-objects) |
| `liabtree` | 余额的 Merkle 求和树；拒绝在兄弟节点之间转移数值的证明 | [线协议键](docs/wire-keys.md#evidence-reviews-and-liabilities) |
| `regpow` | 面向开放注册的 Hub 的注册工作量证明（22 位） | [线协议键](docs/wire-keys.md#labels-and-type-tags) |
| `tsir` | TaskDoc 及其 CID；封闭且有界的谓词演算 | [线协议键](docs/wire-keys.md#task-documents) |
| `effect` | 执行效果记录：发生了什么，以及是否可验证 | [线协议键](docs/wire-keys.md#objects) |
| `agenturi` | `agent://` URI：解析与规范形式 | — |
| `wire` | 注册表、仅用于测试的代码扫描器和 `docs/wire-keys.md` 生成器 | [registry.json](wire/registry.json) |
| `golden` | 一致性向量、向量索引和独立生成器 | [一致性](#conformance) |

### 范围与依赖

函数仅在满足以下条件时才归入本模块：具有确定性、不执行 I/O，且至少由两个应用使用，或由黄金测试向量固定其行为。外部依赖固定为四类——`fxamacker/cbor`、`filippo.io/edwards25519`、`golang.org/x/crypto`、`golang.org/x/text`——以及 multiformats CID 库。体现技术选型的标准库包（例如 `crypto/hpke`）也会记录。向量生成器使用的 Python 库不属于 Go 模块的依赖。参见 [docs/scope.md](docs/scope.md)。

## 文档

**[英文文档](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/)** ·
[简体中文](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/)

| 参考 | 内容 |
|---|---|
| [Go 参考文档](https://pkg.go.dev/github.com/ANetResearch/ANetCore) | 包 API |
| [线协议键](docs/wire-keys.md) | 精确的线协议键、标签、类型标签和构造 |
| [线协议注册表](wire/registry.json) | 已注册的键、标签、操作和原因码 |
| [范围](docs/scope.md) | 内核边界与依赖 |
| [变更日志](CHANGELOG.md) | 版本历史与不兼容的线协议变更 |
| [架构与概念](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/intro/overview.html) | ANet 架构 |
| [身份](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/topics/identity.html) | 身份、密钥轮换与恢复 |
| [消息传输](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/topics/messaging.html) | 封装消息传输与送达确认 |
| [安全模型](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/reference/security.html) | 系统安全保证与限制 |
| [运行 Hub](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/ops/hub.html) | Hub 运维 |

设计背景：[协议参考](https://docs.agentnetwork.org.cn/docs/zh-cn/latest/reference/protocol.html)、[中继绑定](https://github.com/ANetResearch/ANet/blob/main/docs/a2a/relay-binding.md) 草案，以及 [anet-credit](https://github.com/ANetResearch/ANet/blob/main/docs/a2a/x402-scheme-anet-credit.md) 草案。

## 从源码构建

<a id="conformance"></a>
### 一致性

`go test ./...` 是一致性测试套件：

```sh
go test ./...                                  # 金标向量、反例与登记表
go run ./wire/gen -check                       # 核对 docs/wire-keys.md 与登记表一致
python3 golden/py/gen_v016.py --check          # 用独立实现重新生成并比对
```

- **黄金测试向量**覆盖注册表中的线协议对象，以及签名、哈希和密钥派生标签。`golden/testdata/index.json` 记录覆盖情况；覆盖缺失会导致构建失败。
- **反例测试**对每个向量更改一个字节、移除一个必需键或添加一个未注册键。每个反例都必须失败，并给出明确原因。
- **标准测试向量**覆盖包含导出功能的 RFC 9180 HPKE、RFC 8785，以及由 a2a-python 参考 SDK 签名的 A2A 卡片。
- **`TestWireRegistry`** 对照注册表扫描代码。ANet 和 ANetHub 执行相同扫描。

[`golden/py/gen_v016.py`](golden/py/gen_v016.py) 是使用独立密码学库的第二套纯 Python 实现。CI 重新生成每个密码学向量，并逐字节比较。信封向量由 Python 封装、Go 解封，复现签名、信封摘要和送达确认密钥。种子来自公开标签，因此没有任何文件包含真实密钥。

通过这些向量的实现，在向量覆盖的所有内容上均会生成与本实现相同的字节。

<details>
<summary><b>第二套实现必须遵循的规则</b></summary>

- CBOR 使用 CoreDet。已签名消息体以包含其 CoreDet 编码的字节串传输；验证方对解码结果重新编码，若字节不一致，则拒绝该消息体。
- 在外层信封、`Wrap` 和内层消息中，必须理解键 0–63；键 ≥ 64 可以忽略，但仍受签名或摘要保护。其他所有对象均拒绝未注册的键。
- 每次签名、MAC、哈希承诺、KDF 和 HPKE 调用均采用以下两种输入形式之一：键 0 为已注册类型标签的带类型 CBOR；或已注册标签、一个 0x00 字节，以及定长或由 0x00 分隔且绝不包含 U+0000 的字段。精确构造参见 [标签与类型标签](docs/wire-keys.md#labels-and-type-tags)。
- Hub 和 p2p JSON 中的二进制值使用无填充的 base64url。时间使用 Unix 毫秒；一天指 UTC 日 `floor(ms / 86 400 000)`。
- 键编号、标签、relayauth 操作和原因码永不复用；已停用的值会被拒绝。

</details>

### 版本管理与发布验证

ANetCore 使用语义化版本。1.0 之前，次版本可能更改线协议字节；每项此类变更均列于 [CHANGELOG.md](CHANGELOG.md) 的 *Breaking* 部分。补丁版本绝不更改字节。已发布的向量、CID 前缀和套件测试密钥均保持固定。

Go 模块发布版本通过公共校验和数据库验证。基于此内核构建的 `anet` 二进制文件使用 anet 发布密钥签名；参见 ANet 的 [SECURITY.md](https://github.com/ANetResearch/ANet/blob/main/SECURITY.md)。

<a id="community-and-contributing"></a>
## 社区与贡献

- **问题与建议：** [GitHub 讨论](https://github.com/ANetResearch/ANet/discussions)。
- **缺陷与拉取请求：** [问题跟踪](https://github.com/ANetResearch/ANetCore/issues)。任何更改线协议字节的工作均须先创建 issue。
- **安全报告：** hi@anet0.com，主题为 `[SECURITY]` （[SECURITY.md](https://github.com/ANetResearch/ANet/blob/main/SECURITY.md)）。

<a id="license"></a>
## 许可证

**ANet Open Source License** 是经修改的 Apache License 2.0（[LICENSE](LICENSE)），与 ANet 和 ANetHub 使用相同许可证。允许商业使用，包括在产品中作为库使用；标志条款不适用于库使用。为第三方运营多租户托管 Hub 须取得书面授权。A2A 规范工作（ANet `docs/a2a/`）以及向 A2A 项目贡献的代码使用未经修改的 Apache-2.0。相关问题请联系 hi@anet0.com。