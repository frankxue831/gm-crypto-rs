# gm-crypto-rs（中文说明）

[English](README.md) | 中文

纯 Rust 实现的国密算法 SM2 / SM3 / SM4（GB/T 32918 / 32905 / 32907），`no_std` 核心，不依赖 C 库；另提供 C ABI，可供 C、C++、Python、Go、Zig 调用。

**先在浏览器里试试：** [gm-crypto-web](https://www.frankxue.dev/gm-crypto-web/?lang=zh) 用这个库编译成的 WebAssembly 在本地计算 SM2 / SM3 / SM4，不上传数据（未经审计的演示工具，请勿使用生产密钥）。

> ⚠️ **未经第三方安全审计。** 这是个人维护的开源项目，2026 年首次发布，没有支持承诺。现有保障都来自项目内部：CI 里的标准向量测试、与 GmSSL 3.2.0 的互通测试、`dudect` 计时检测、35 个 `cargo-fuzz` 目标。请自行审阅代码后再使用。威胁模型和漏洞报告方式见 [`SECURITY.md`](SECURITY.md)。

## 安装

```bash
cargo add gmcrypto-core
```

```toml
[dependencies]
gmcrypto-core = "1.17"
getrandom = { version = "0.4", default-features = false, features = ["sys_rng"] }
```

默认构建包含 SM2、SM3、SM4-ECB/CBC/CTR、HMAC-SM3、PBKDF2-HMAC-SM3，以及 DER / PEM / PKCS#8 编解码。其余功能需要打开 feature（见下表）。库本身不带随机数生成器，SM2 签名和加密接受任意 `rand_core::TryCryptoRng`，一般用 `getrandom` 的 `SysRng`。

## 最小示例：SM3 和 SM4

```rust
use gmcrypto_core::{sm3, sm4};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SM3 摘要（32 字节）
    let digest = sm3::hash(b"abc");
    assert_eq!(digest.len(), 32);

    // SM4-CBC 加解密（PKCS#7 填充）。key 和 iv 都要用安全随机数生成，iv 不能复用。
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    getrandom::fill(&mut key)?;
    getrandom::fill(&mut iv)?;
    let ct = sm4::mode_cbc::encrypt(&key, &iv, b"hello sm4");
    let pt = sm4::mode_cbc::decrypt(&key, &iv, &ct).ok_or("解密失败")?;
    assert_eq!(pt, b"hello sm4");
    Ok(())
}
```

## SM2 签名和验签

```rust
use gmcrypto_core::sm2::{DEFAULT_SIGNER_ID, Sm2PrivateKey, sign_with_id, verify_with_id};
use getrandom::SysRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 新建 SM2 私钥：取 32 字节随机数；极小概率（约 2^-32）落在 [1, n-2] 之外时重取。
    // 也可以用 `pkcs8`、`sec1`、`pem` 模块加载已有私钥。
    let key = loop {
        let mut secret_32 = [0u8; 32];
        getrandom::fill(&mut secret_32)?;
        if let Some(key) = Sm2PrivateKey::from_bytes_be(&secret_32).into_option() {
            break key;
        }
    };
    let sig = sign_with_id(&key, DEFAULT_SIGNER_ID, b"hello", &mut SysRng)?;
    assert!(verify_with_id(&key.public_key(), DEFAULT_SIGNER_ID, b"hello", &sig));
    Ok(())
}
```

更多示例（SM2 密钥交换、X.509 等）见[英文 README](README.md#more-examples)。

## 功能一览

| 功能 | 标准 | feature |
|---|---|---|
| SM2 签名 / 验签、加密 / 解密 | GB/T 32918，GM/T 0009 DER | 默认 |
| SM3、HMAC-SM3、PBKDF2-HMAC-SM3 | GB/T 32905，RFC 2104 / 8018 | 默认 |
| SM4-ECB / CBC / CTR（一次性和流式） | GB/T 32907 | 默认 |
| DER / PEM / SPKI / SEC1 / PKCS#8（含 PBES2 加密） | RFC 5280 / 5915 / 5958 / 7468 | 默认 |
| SM4-GCM / SM4-CCM | — | `sm4-aead` |
| SM4-XTS（仅保密性） | GB/T 17964-2021 | `sm4-xts` |
| SM2 密钥交换（含密钥确认） | GM/T 0003.3 | `sm2-key-exchange` |
| X.509（SM2）证书解析、验证和线性链验证 | GM/T 0015 | `x509` |
| TLCP 密钥派生、记录保护、签名 / 加密证书对验证 | GB/T 38636-2020 | `tlcp` |

C 语言等调用方请用 [`gmcrypto-c`](crates/gmcrypto-c/README.md)。`gmcrypto-simd` 是内部后端，不要直接依赖。

## 计时检测是怎么做的

涉及密钥的代码按常量时间的写法实现（基于 `subtle`）。项目在 CI 里用 [`dudect-bencher`](https://docs.rs/dudect-bencher/) 检查这一点：每个 PR 和每晚，对 20 个涉及密钥的操作分两类输入计时并比较。其中 16 个在 `|tau|` 超过 0.20 时阻止合并，另有一个故意泄漏的对照组每次都必须被检出，用来证明检测本身还有效。

这种检测只能说明**在给定样本量下没有检出**计时差异，不能证明没有。完整说明和历史数据见 [`SECURITY.md`](SECURITY.md)。

此外，CI 每次都会和 GmSSL 3.2.0（参考实现，固定版本从源码构建）跑 13 项互通测试，逐字节比对签名、密文和 AEAD 输出。这项测试目前不阻止合并。

## 本库提供什么

| | 本库 | 在哪里核对 |
|---|---|---|
| CI 计时检测 | ✅ 用 `dudect` 检测 20 个涉及密钥的操作，外加一个必须被检出的对照组；其中 16 个超过阈值会阻止合并。改动密码学代码的 PR 和每晚都会跑 | [`dudect-pr.yml`](.github/workflows/dudect-pr.yml)、[`dudect-nightly.yml`](.github/workflows/dudect-nightly.yml) |
| CI 模糊测试 | ✅ 35 个 `cargo-fuzz` 目标，每晚运行 | [`fuzz-nightly.yml`](.github/workflows/fuzz-nightly.yml)、[`fuzz/fuzz_targets`](fuzz/fuzz_targets) |
| 与 GmSSL 3.2.0 互通 | ✅ 每次 CI 跑 13 项逐字节比对（签名、密文、AEAD） | [`ci.yml`](.github/workflows/ci.yml) |
| SM4 S 盒 | ✅ 默认不用密钥相关的字节查表（扫描全部 256 项，速度较慢；可选 bitsliced / SIMD） | [`sm4/cipher.rs`](crates/gmcrypto-core/src/sm4/cipher.rs) |
| C ABI | ✅ 112 个入口函数 | [`gmcrypto-c`](crates/gmcrypto-c) |
| `no_std` | ✅ `no_std` + `alloc`；CI 构建 wasm32 | [`ci.yml`](.github/workflows/ci.yml) |
| **第三方安全审计** | **没有** | [`SECURITY.md`](SECURITY.md) |
| **实际使用记录** | **很少：2026 年首次发布，一个人维护** | [`CHANGELOG.md`](CHANGELOG.md) |

如果你需要长期的实际使用记录，RustCrypto 的 `sm2` / `sm3` / `sm4` 和 `libsm` 更成熟、用的人也多得多，更适合你。

## 不包含什么

- 不是完整的 TLS / TLCP 协议实现：`tlcp` 只提供密码学构建模块，没有握手状态机和传输层。
- 不包含 SM9、ZUC 和后量子算法。
- 不是 HSM / SDF / SKF 集成，也不是经过认证的密码模块。
- 在乘法耗时依赖数据的 CPU（部分老 x86、部分嵌入式）上，常量时间写法不成立。
- `verify_chain` / `verify_pair` 只做结构上的信任判断：返回 `true` 表示证书链连到了你提供的根，不代表对方就是你要连接的那个服务器。

## 许可证

MIT 或 Apache-2.0，二选一。英文 [README](README.md) 是主文档；两者不一致时以英文版为准。
