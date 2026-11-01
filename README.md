# whatsapp-signal-protocol · Signal 协议 Python 实现

<a id="contact"></a>

## Telegram Contact: [@ttjjda](https://t.me/ttjjda)

[中文](#zh) · [English](#en) · [从这里开始](#start-here) · [Start Here](#start-here-en) · [Contact](#contact) · [GPLv3](LICENSE)

<a id="zh"></a>

## 中文

**把 Signal 消息加密、双棘轮与后量子建链，直接放进你的 Python 工程。**

从第一条 PreKey 消息，到双向回复、乱序解密和群组 Sender Key，这个库提供完整的协议流程、明确的状态转换和可复现的测试。默认模式对应 `libsignal-protocol-java`，WhatsApp 模式补齐 v4 混合建链及其消息、校验与生命周期行为。

用 `pyproject.toml` 安装和构建，以 Python API 操作协议；运行时无需 JVM、Java 服务或手机。曲线与 AES 等密码学算术使用 PyNaCl/libsodium、cryptography，正常 ML-KEM 运算使用原生 PQClean。

<a id="start-here"></a>

### 从这里开始

需要 Python 3.9 或更高版本。项目名称为 `whatsapp-signal-protocol`，Python 导入名为 `signal_protocol`。进入项目目录后执行：

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

python examples/roundtrip.py
python examples/whatsapp_v4.py
python -m pytest
```

[双向会话示例](examples/roundtrip.py)会生成双方身份与预密钥，完成握手、加密、解密和回复。[v4 示例](examples/whatsapp_v4.py)继续演示 ML-KEM-1024/X25519 建链、业务 padding，以及成功接收后的预密钥消费。示例全部在本地内存中运行。

### 开箱即用的协议能力

| 能力 | 已实现内容 |
| --- | --- |
| 单聊 | PreKey 建链、Double Ratchet、双向收发、乱序缓存与重复消息检测 |
| 后量子建链 | v4 X25519 + ML-KEM-512/768/1024，签名 KEM 预密钥与完整状态字段 |
| 群组 | Sender Key、密钥分发、签名认证与乱序消息 |
| 消息与状态 | Signal / PreKey / SenderKey protobuf、会话序列化、历史状态与密钥消费 |
| 身份验证 | Curve25519 签名、严格公钥条件校验、数字安全码与二维码指纹 |
| 一致性 | VRF、设备一致性承诺与校验码 |

### 选择协议模式

| 使用方式 | 行为 |
| --- | --- |
| `SessionBuilder` / `SessionCipher` | 默认 UPSTREAM 模式，对应 Java 上游的 v3 行为 |
| `WhatsAppSessionBuilder` / `WhatsAppSessionCipher` | WhatsApp 模式，支持 v3/v4 建链，自动处理业务 padding |
| `SessionCipher(..., profile=WHATSAPP)` | 使用 WhatsApp 协议行为，由调用方自行处理内容与业务 padding |
| `WhatsAppGroupCipher` | 为群组 Sender Key 提供相同的业务 padding 适配 |

WhatsApp 模式解析原始密文时显式提供 `message_type=2/3`。直接使用消息或记录解析器时，也要传入 `profile=WHATSAPP`，例如 `SignalMessage.from_bytes(data, profile=WHATSAPP)`。

完整且签名有效的 KEM bundle 建立 v4；没有 KEM 的 bundle 建立 v3。不完整或无效的 KEM 材料会报错，不自动降级。KEM 默认使用 1024，也可显式选择：

```python
from signal_protocol import KemKeyType, KeyHelper

# bob_store 是调用方已准备的协议 Store。
kem_record = KeyHelper.generate_kyber_pre_key(
    bob_store.identity_key_pair,
    9,
    key_type=KemKeyType.ML_KEM_768,
)
```

三档采用 raw 公钥、展开私钥与密文编码，导入时可由长度识别参数。v4 KDF 均保留 `WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024` 标签；实际原语是 ML-KEM，不能按历史标签替换成旧 Kyber Round 3。

### 接入自己的工程

协议逻辑与应用存储通过 [Store 契约](src/signal_protocol/store_contracts.py)连接。内存 Store 可直接用于测试；生产存储负责保存密钥、会话和 Sender Key 记录，加载时返回独立对象，并串行化同一会话的读改写。KEM Store 还需保留 `last_resort` 元数据。

消息和记录使用 `serialize()` / `from_bytes()`，接口采用 `snake_case`。解密回调在 session 保存前执行；认证失败不提交棘轮状态，一次性预密钥在成功接收并保存 session 后消费。外部 Store 的多个操作不自动组成数据库事务。

密钥材料、显式种子和签名随机量使用 `bytes`、`bytearray` 或 `memoryview` 等字节缓冲区；整数和列表会被拒绝，避免将字节长度误作全零密钥或随机量。可变缓冲区在导入时复制。Java `int` ID 和计数器按相同的 32 位模式进行保存与查找。

库的范围是算法、消息格式、密钥派生与协议状态。账号注册、连接传输、JID/设备管理和消息业务由上层应用组织。本项目为独立、非官方实现，与 WhatsApp 或 Meta 无官方隶属或背书关系。

### 用测试说话

| 验证 | 已保存结果 |
| --- | --- |
| Python 回归 | **789/789** |
| 原 Java / Python 双向互通 | **20/20** |
| WhatsApp 实际引擎受控对照 | **37/37 组** |
| 原 Java 官方 JNI 后端 | **45/45** |

实际引擎验证覆盖三档 ML-KEM、双方发起、有/无 Curve 一次性预密钥、乱序棘轮、群组、padding、公钥与解析边界、计数器回绕和 Store 回调。输入是独立生成的合成密钥与内存会话。实际引擎调用已保存为[离线测试向量](tests/vectors)，普通 pytest 无需手机或 Frida。

本地回归还覆盖共享 Store 的并发会话、跳过消息密钥的有符号计数器查找、二维码指纹与设备一致性消息的 Java Protobuf 解析边界，以及密钥和随机量输入校验。

原桌面 Java 依赖 `curve25519-java:0.5.0` 的 VRF 方法未实现，原样基线为 **44/45**；该失败保留，官方 JNI 后端运行相同协议场景通过。JNI 测试在本机 JVM 执行，不是 Android instrumentation。Java 源测试按原循环、固定向量和异常断言移植；仅 provider 选择断言按 Python 后端适配。

Python 回归和分发包构建可直接从本仓库运行：

```sh
python -m pytest
python -m pip install build
python -m build
```

可选的 `tests/interop` 需要额外的 Java 参考源码和本地验证工具；Java/Frida 工具及原始分析报告不随本仓库和分发包发布。普通 pytest 不依赖这些工具。已保存的 Java 对照使用 `javac --release 8` 与 protobuf-javalite 3.21.12，不代表原 Gradle/Android 构建任务通过。

### 项目结构

```text
whatsapp-signal-protocol/
├── README.md
├── pyproject.toml
├── src/signal_protocol/    # 协议实现与 protobuf schema
├── tests/                 # 回归测试与公开合成向量
├── examples/              # 本地双向会话与 v4 示例
├── LICENSE
└── NOTICE
```

`src/signal_protocol/` 保持扁平布局，按职责划分：

| 模块 | 职责 |
| --- | --- |
| `session.py`、`groups.py`、`store.py` | 保留既有导入路径，显式重新导出公开接口 |
| `session_builder.py` | 验证 PreKey bundle，初始化发送与接收会话 |
| `session_cipher.py` | 组合建链逻辑与调用方 Store，执行双棘轮和有序提交 |
| `group_session.py` | Sender Key 分发与群组加解密流程 |
| `state.py`、`sender_keys.py` | 单聊与群组状态、密钥派生及 protobuf 序列化 |
| `address.py`、`store_contracts.py` | 地址、信任方向与独立的存储契约 |
| `memory_store.py` | 通过序列化隔离读写对象的内存存储实现 |
| `adapters.py`、`whatsapp.py` | WhatsApp 内容 padding、解码与公钥条件校验 |
| `protocol.py`、`protobuf_codec.py`、`integers.py` | 消息封装、Java protobuf 解析语义与统一整数转换 |
| `ecc.py`、`kem.py`、`kdf.py`、`keys.py`、`ratchet.py` | 密码学原语、密钥记录和棘轮派生 |
| `fingerprint.py`、`devices.py`、`vrf.py` | 指纹、设备一致性与 VRF |

依赖从适配器、会话流程指向状态和密码学模块；协议流程不导入具体内存 Store，也不通过兼容入口模块访问内部实现。调用方可继续使用 `from signal_protocol import SessionCipher`，以及 `signal_protocol.session`、`signal_protocol.groups`、`signal_protocol.store` 的既有接口。单独执行 `import signal_protocol` 后仍可访问 `signal_protocol.groups`；搬迁类保留原公开模块名，使原本可 pickle 的对象仍可由旧版读取。手写模块用 `__all__` 明确公开名字；生成的 protobuf 文件保持生成器输出。

`SessionCipher` 组合 `SessionBuilder` 与注入的 Store。构造器仍可分别接收 `pre_key_store`、`signed_pre_key_store`、`identity_key_store`、`kyber_pre_key_store`；未提供时使用首个 `store`。现有适配器和组合内存 Store 的继承关系保留，以兼容调用方子类。两个协议流程各自复用唯一共享锁；解密、去 padding 和应用回调均在持久化之前完成。

测试统一放在 `tests/`，新模块的导入兼容、独立 Store 注入和回调失败重试见 [test_module_api.py](tests/test_module_api.py)。新增存储后端应实现相应契约，并保持加载对象独立与失败时不提交会话或 Sender Key 状态的语义。

### 密钥与实现边界

**测试向量中包含公开的合成私钥、种子和共享秘密。** 它们用于逐字节复现测试，不是账号凭据，不能用于真实通信。安装 wheel 不包含这些测试向量；源码分发包保留它们以支持复现。应用生成的真实密钥、Store 导出、令牌和认证材料应保存在应用自己的私有存储中。

正常密钥使用原生密码学算术；显式 seed 或 `backend="reference"` 的 KEM 使用 kyber-py 参考实现。UPSTREAM 模式为兼容历史未 clamp 私钥而提供 Python DH 路径。这些参考/兼容路径不保证常数时间，整个库尚未经过独立密码学安全审计。

计数器按 Java 的 int32 比较与 uint32 回绕处理；对可能导致超大循环的畸形导入状态，Python 始终限制一次派生最多 2000 步。签名验证保留原 ref10 接受语义，包括符合其高位检查的 `S+L`。`KeyExchangeMessage` schema 与 pending 状态保留；给定上游没有交互式建链 API，因此未另造该 API。

### 联系与贡献

协议交流、使用反馈与合作联系：**Telegram [@ttjjda](https://t.me/ttjjda)**。欢迎提交可复现问题、测试向量和中英文改进；问题中请使用合成或脱敏数据。

移植自 Open Whisper Systems 的 GPLv3 源码，上游基准为 `fde96d22004f32a391554e4991e4e1f0a14c2d50`。保留 [LICENSE](LICENSE) 与 [NOTICE](NOTICE)。

---

<a id="en"></a>

## English

**Bring Signal message encryption, the Double Ratchet, and post-quantum session setup into your Python project.**

From the first PreKey message to replies, out-of-order decryption, and group Sender Keys, this library provides the protocol flow, explicit state transitions, and reproducible tests. The default profile follows `libsignal-protocol-java`. The WhatsApp profile adds hybrid v4 setup and the corresponding message, validation, and lifecycle behavior.

Install and build with `pyproject.toml`, then use Python APIs without a JVM, Java service, or phone at runtime. Curve and AES arithmetic use PyNaCl/libsodium and cryptography; normal ML-KEM operations use native PQClean implementations.

<a id="start-here-en"></a>

### Start here

Requires Python 3.9 or later. The project name is `whatsapp-signal-protocol`; its Python import name is `signal_protocol`. From the project directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'

python examples/roundtrip.py
python examples/whatsapp_v4.py
python -m pytest
```

The [two-party example](examples/roundtrip.py) generates identities and prekeys, establishes a session, encrypts, decrypts, and replies. The [v4 example](examples/whatsapp_v4.py) adds ML-KEM-1024/X25519 setup, content padding, and prekey consumption after successful reception. Both examples run entirely in local memory.

### Protocol capabilities

| Area | Included |
| --- | --- |
| Direct messages | PreKey setup, Double Ratchet, bidirectional exchange, skipped-key caching, duplicate detection |
| Post-quantum setup | v4 X25519 + ML-KEM-512/768/1024, signed KEM prekeys, complete state fields |
| Groups | Sender Keys, distribution messages, signature authentication, out-of-order reception |
| Messages and state | Signal / PreKey / SenderKey protobuf, session serialization, archives, key consumption |
| Identity verification | Curve25519 signatures, conditional strict public-key validation, numeric and QR fingerprints |
| Consistency | VRF, device-consistency commitments and codes |

### Choose a profile

| API | Behavior |
| --- | --- |
| `SessionBuilder` / `SessionCipher` | Default UPSTREAM profile, matching the Java upstream's v3 behavior |
| `WhatsAppSessionBuilder` / `WhatsAppSessionCipher` | WhatsApp profile, v3/v4 setup with automatic content padding |
| `SessionCipher(..., profile=WHATSAPP)` | WhatsApp protocol behavior with caller-managed content and padding |
| `WhatsAppGroupCipher` | The same content-padding adapter for group Sender Keys |

Supply `message_type=2/3` explicitly when decrypting raw ciphertext through the WhatsApp adapter. Pass `profile=WHATSAPP` to direct message and record parsers as well, for example `SignalMessage.from_bytes(data, profile=WHATSAPP)`.

A complete KEM bundle with a valid signature establishes v4; a bundle without KEM establishes v3. Incomplete or invalid KEM material raises an error without an automatic downgrade. ML-KEM-1024 is the default; select another parameter set explicitly:

```python
from signal_protocol import KemKeyType, KeyHelper

# bob_store is the protocol Store already prepared by the caller.
kem_record = KeyHelper.generate_kyber_pre_key(
    bob_store.identity_key_pair,
    9,
    key_type=KemKeyType.ML_KEM_768,
)
```

All three sets use raw public keys, expanded secret keys, and ciphertexts. Imports can infer the parameter set from length. Their v4 KDF retains `WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024`; the primitive is ML-KEM, so the historical label must not be used to substitute legacy round-3 Kyber.

### Integrate with your application

The [Store contracts](src/signal_protocol/store_contracts.py) connect protocol logic to application storage. Use the in-memory Store for tests. Production stores save keys, sessions, and Sender Key records, return independent objects on load, and serialize read-modify-write operations for each session. KEM stores must also retain `last_resort` metadata.

Messages and records expose `serialize()` / `from_bytes()` with `snake_case` APIs. Decryption callbacks run before the session is saved. Authentication failures do not commit ratchet state; one-time prekeys are consumed after successful reception and session storage. Multiple external Store operations do not automatically form a database transaction.

Key material, explicit seeds, and signature randomness use byte buffers such as `bytes`, `bytearray`, or `memoryview`. Integers and lists are rejected to prevent treating a byte count as an all-zero key or randomness. Mutable buffers are copied on import. Java `int` IDs and counters use the same 32-bit representation for storage and lookup.

The library covers algorithms, message formats, key derivation, and protocol state. Registration, transport, JID/device management, and message business logic belong to the application layer. This independent, unofficial implementation is not affiliated with or endorsed by WhatsApp or Meta.

### Verified beyond a local round trip

| Verification | Recorded result |
| --- | --- |
| Python regression suite | **789/789** |
| Original Java / Python bidirectional interoperability | **20/20** |
| Controlled comparisons with the actual WhatsApp engine | **37/37 groups** |
| Original Java tests with the official JNI backend | **45/45** |

Engine checks cover all three ML-KEM sets, both initiators, optional Curve one-time prekeys, out-of-order ratchets, groups, padding, public-key and parser boundaries, counter wraparound, and Store callbacks. Inputs use independently generated synthetic keys and in-memory sessions. Recorded engine calls are retained as [offline test vectors](tests/vectors); ordinary pytest runs require neither a phone nor Frida.

Local regressions also cover concurrent sessions sharing a Store, signed-counter lookups for skipped message keys, Java Protobuf parsing boundaries for QR fingerprints and device consistency messages, and validation of key and randomness inputs.

The original desktop dependency, `curve25519-java:0.5.0`, leaves its VRF methods unimplemented, giving an unchanged **44/45** baseline. That failure is retained; the official JNI backend passes the same protocol scenarios. JNI tests execute on the host JVM, not through Android instrumentation. Java scenarios preserve their original loops, fixed vectors, and exception checks; provider-selection assertions are adapted to the Python backend.

Run Python regression tests and build distributions directly from this repository:

```sh
python -m pytest
python -m pip install build
python -m build
```

Optional `tests/interop` checks require additional Java reference sources and local verification tools. Java/Frida tools and raw analysis reports are excluded from this repository and its distributions. Ordinary pytest runs do not depend on them. Recorded Java comparisons use `javac --release 8` and protobuf-javalite 3.21.12; they do not claim that the original Gradle/Android build tasks pass.

### Project structure

```text
whatsapp-signal-protocol/
├── README.md
├── pyproject.toml
├── src/signal_protocol/    # Protocol implementation and protobuf schemas
├── tests/                 # Regression tests and public synthetic vectors
├── examples/              # Local two-party and v4 examples
├── LICENSE
└── NOTICE
```

`src/signal_protocol/` keeps a flat layout with focused responsibilities:

| Modules | Responsibility |
| --- | --- |
| `session.py`, `groups.py`, `store.py` | Preserve existing import paths through explicit public re-exports |
| `session_builder.py` | Validate PreKey bundles and initialize outgoing/incoming sessions |
| `session_cipher.py` | Compose session setup and caller-supplied stores for ratcheting and ordered commits |
| `group_session.py` | Sender Key distribution and group encryption/decryption |
| `state.py`, `sender_keys.py` | Direct/group state, key derivation and protobuf serialization |
| `address.py`, `store_contracts.py` | Addresses, trust directions and independent storage contracts |
| `memory_store.py` | Memory stores that isolate loaded and saved objects through serialization |
| `adapters.py`, `whatsapp.py` | WhatsApp content padding, decoding and conditional public-key checks |
| `protocol.py`, `protobuf_codec.py`, `integers.py` | Message envelopes, Java protobuf parsing semantics and shared integer conversion |
| `ecc.py`, `kem.py`, `kdf.py`, `keys.py`, `ratchet.py` | Cryptographic primitives, key records and ratchet derivation |
| `fingerprint.py`, `devices.py`, `vrf.py` | Fingerprints, device consistency and VRFs |

Dependencies point from adapters and session workflows toward state and cryptographic modules. Protocol workflows do not import concrete memory stores or access implementations through compatibility entry modules. Existing imports such as `from signal_protocol import SessionCipher` and APIs in `signal_protocol.session`, `signal_protocol.groups` and `signal_protocol.store` remain available. A plain `import signal_protocol` still exposes `signal_protocol.groups`. Relocated classes retain their original public module names so previously picklable objects remain readable by older installations. Handwritten modules declare public names with `__all__`; generated protobuf files retain their generator output.

`SessionCipher` composes a `SessionBuilder` with injected stores. Constructors still accept separate `pre_key_store`, `signed_pre_key_store`, `identity_key_store` and `kyber_pre_key_store` arguments, defaulting to the initial `store` when omitted. Existing adapter and aggregate memory-store inheritance is retained for compatibility with caller subclasses. Direct and group workflows each reuse a single shared lock; decryption, unpadding and application callbacks all complete before persistence.

Tests live consistently under `tests/`. See [test_module_api.py](tests/test_module_api.py) for import compatibility, separate store injection and retries after callback failures. New storage backends should implement the relevant contracts while preserving independent loaded objects and avoiding session or Sender Key state commits on failure.

### Keys and implementation boundaries

**Test vectors contain public synthetic private keys, seeds, and shared secrets.** They support byte-for-byte reproduction, are not account credentials, and must never be used for real communication. Installation wheels exclude these vectors; source distributions retain them for reproducibility. Keep application-generated keys, Store exports, tokens, and authentication material in your application's private storage.

Normal keys use native cryptographic arithmetic. Explicit seeds or `backend="reference"` select the kyber-py reference implementation. UPSTREAM also provides a Python DH compatibility path for historical unclamped private keys. These reference/compatibility paths do not guarantee constant-time execution. The library has not undergone an independent cryptographic security audit.

Counters follow Java int32 comparisons and uint32 wraparound. Python always caps a single derivation at 2000 steps for malformed imported states that could otherwise cause enormous loops. Signature verification preserves the original ref10 acceptance rules, including `S+L` encodings that pass its high-bit check. The `KeyExchangeMessage` schema and pending state are retained; no interactive setup API is invented where the supplied upstream has none.

### Contact and contribute

For protocol discussions, feedback, and collaboration: **Telegram [@ttjjda](https://t.me/ttjjda)**. Reproducible issues, test vectors, and Chinese/English improvements are welcome. Use synthetic or redacted data in reports.

Ported from Open Whisper Systems' GPLv3 sources at upstream revision `fde96d22004f32a391554e4991e4e1f0a14c2d50`. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
