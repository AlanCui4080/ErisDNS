# 写在前面
本工程完全使用 DeepSeekV4-Pro 编写，花费为 10.5CNY, 共消耗 38,790,507 Tokens， opencode 自由运行时长 ~70Mins 。当然，在编写本工程时 DeepSeek 的该款模型有 -75% 的优惠。

> DeepSeek‑V4‑Pro：总参数1.6T，激活参数49B

- 在第一轮对话中，要求其编写一个完整的 DNS 解析和服务器。
- 在第二轮对话中，要求其下载相关 RFC 并针对 RFC 编写正反测试用例。
- 在第三轮对话中，我审查了代码，指出了架构的一些问题，要求改正。
- 在第四轮对话中，要求其加入模糊测试。
- 在第五轮对话中，我首次运行了该程序，发现默认参数根本跑不起来，要求其加入基于产物的测试。
- 在第六轮对话中，要求其实现递归查询，我纠正了持续数十分钟的思维链死循环。
- 在第七轮对话中，要求其编写文档。

本项目测试共 2500 行整，源码共 1637 行。

未经审查，不对代码库负任何有限的无限的亦或是连带的责任。

以下是模糊测试覆盖率：
Filename                             Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
src/dns_parser.cpp                       123                 3    97.56%          20                 1    95.00%         300                10    96.67%          76                 3    96.05%
src/dns_resolver.cpp                      24                 4    83.33%           5                 0   100.00%          63                 9    85.71%          22                 8    63.64%
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

以下是测试覆盖率（可以看到反向测试用例完全没测到dns_resolver，所以小心爆炸）：
=== test_parser ===
Filename                             Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
src/dns_parser.cpp                       123                20    83.74%          20                 1    95.00%         300                55    81.67%          76                20    73.68%
src/dns_resolver.cpp                      24                 6    75.00%           5                 0   100.00%          63                 9    85.71%          22                10    54.55%
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


=== test_negative ===
Filename                             Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
src/dns_parser.cpp                       123                44    64.23%          20                10    50.00%         300               117    61.00%          76                35    53.95%
src/dns_resolver.cpp                      24                24     0.00%           5                 5     0.00%          63                63     0.00%          22                22     0.00%
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


=== test_class ===
Filename                             Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
src/dns_parser.cpp                       123                12    90.24%          20                 1    95.00%         300                29    90.33%          76                12    84.21%
src/dns_resolver.cpp                      24                 0   100.00%           5                 0   100.00%          63                 0   100.00%          22                 1    95.45%
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


=== test_semi_fuzz ===
Filename                             Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
src/dns_parser.cpp                       123                 7    94.31%          20                 1    95.00%         300                14    95.33%          76                 7    90.79%
src/dns_resolver.cpp                      24                 0   100.00%           5                 0   100.00%          63                 0   100.00%          22                 0   100.00%
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

=== test_product ===
Filename                             Regions    Missed Regions     Cover   Functions  Missed Functions  Executed       Lines      Missed Lines     Cover    Branches   Missed Branches     Cover
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
src/dns_cache.cpp                         56                56     0.00%          13                13     0.00%          86                86     0.00%          40                40     0.00%
src/dns_parser.cpp                       123                34    72.36%          20                 1    95.00%         300                87    71.00%          76                32    57.89%
src/dns_recursive.cpp                    157               135    14.01%          19                10    47.37%         393               323    17.81%         120               112     6.67%
src/dns_resolver.cpp                      24                24     0.00%           5                 5     0.00%          63                63     0.00%          22                22     0.00%
src/dns_server.cpp                        43                43     0.00%          14                14     0.00%         205               205     0.00%          18                18     0.00%
src/dns_upstream.cpp                      74                74     0.00%           8                 8     0.00%         159               159     0.00%          44                44     0.00%
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# ErisDNS

C++23 递归 DNS 解析器服务器，基于 Boost.Asio 实现，支持 UDP/TCP 双协议、本地权威区、递归解析与上游转发。

## 特性

- **双协议服务器** — UDP（512B 截断 + TC 位）+ TCP（2 字节长度前缀帧，RFC 1035 §4.2.2）
- **递归解析** — 本地区 → NXDOMAIN 缓存 → 应答缓存 → CNAME 链追踪 → 根提示迭代 / 上游转发
- **上游转发模式** — 指定唯一上游服务器，跳过根提示递归，RD=1 递归查询
- **本地权威区** — 支持添加 A / AAAA / CNAME / TXT / MX / SOA 等区记录
- **TTL 缓存** — 线程安全（shared_mutex），支持应答缓存、NXDOMAIN 负缓存、NS 委派缓存
- **RFC 合规** — 遵循 RFC 1034/1035/6891，包含 150+ 测试用例

## 依赖

| 依赖 | 版本 |
|------|------|
| CMake | ≥ 3.31 |
| C++ 编译器 | GCC ≥ 13 / Clang ≥ 17（需 C++23 支持） |
| Boost | ≥ 1.82（headers + unit_test_framework） |

## 构建

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## 运行

```bash
# 默认：监听 5353 端口，上游转发至 192.168.5.252
./build/erisdns

# 自定义端口和上游
./build/erisdns 53 8.8.8.8
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `argv[1]` 端口 | `5353` | UDP/TCP 监听端口 |
| `argv[2]` 上游 | `192.168.5.252` | 上游 DNS 转发器地址 |

使用 `dig` 测试：

```bash
dig @127.0.0.1 -p 5353 www.baidu.com A
dig @127.0.0.1 -p 5353 example.local A    # 本地区记录
```

按 `Ctrl+C` 优雅关闭。

## 测试

```bash
cmake --build build -j$(nproc)
ctest --test-dir build --output-on-failure
```

| 测试目标 | 说明 | 用例数 |
|----------|------|--------|
| `test_parser` | 解析器 / 序列化器 / 简单解析器基础功能 | 15 |
| `test_negative` | 截断输入、指针环、非法标签等畸形报文鲁棒性 | 15 |
| `test_class` | RFC 1034/1035/6891 逐节合规性测试 | ~40 |
| `test_product` | RecursiveResolver 端到端集成测试 | 12 |
| `test_semi_fuzz` | 位翻转、边界值、指针破坏、序列化不变量等半模糊测试 | ~30 |
| `fuzz_parser` | LibFuzzer 全模糊测试（仅 Clang） | — |

LibFuzzer 模糊测试（需要 Clang）：

```bash
cmake -B build_fuzz -DCMAKE_CXX_COMPILER=clang++
cmake --build build_fuzz --target fuzz_parser -j$(nproc)
./build_fuzz/fuzz_parser -max_total_time=60
```

## 架构

```
                    ┌─────────────┐
  DNS 客户端 ──UDP/TCP──▶│  DnsServer   │
                    └──────┬──────┘
                           │ resolve(callback)
                    ┌──────▼──────────────┐
                    │  RecursiveResolver   │
                    ├──────────────────────┤
                    │ 1. 本地权威区查询     │
                    │ 2. NXDOMAIN 负缓存    │
                    │ 3. 应答缓存           │
                    │ 4. 上游转发/根提示递归 │
                    │ 5. CNAME 链追踪       │
                    └──────┬──────────────┘
                           │ std::thread (异步)
                    ┌──────▼──────┐
                    │ UpstreamClient│
                    │ UDP → TCP    │
                    └─────────────┘
```

**关键设计决策**：上游查询在 `std::thread` 中执行，完成后通过 `asio::post(io_, callback)` 回调主事件循环，避免阻塞服务器的 I/O 线程。

## 模块

| 头文件 | 类 | 职责 |
|--------|-----|------|
| `dns_types.hpp` | `Header`, `Question`, `ResourceRecord`, `Message` | DNS 报文核心数据类型 |
| `dns_parser.hpp` | `Parser`, `Serializer` | 线格式 ↔ 结构化消息转换，支持指针压缩 |
| `dns_resolver.hpp` | `Resolver` | 简单权威解析器（单元测试用） |
| `dns_cache.hpp` | `DnsCache` | TTL 缓存，线程安全，支持 NXDOMAIN / NS 委派 |
| `dns_upstream.hpp` | `UpstreamClient` | 上游 DNS 查询客户端，UDP 优先 + TC 时 TCP 回退 |
| `dns_recursive.hpp` | `RecursiveResolver` | 递归解析器，整合缓存、本地区、转发/递归 |
| `dns_server.hpp` | `DnsServer` | 异步 UDP + TCP DNS 服务器 |

## 解析流程

```
收到查询
  │
  ├─ 本地权威区匹配 ──▶ 直接返回（AA=1）
  │
  ├─ NXDOMAIN 缓存命中 ──▶ 返回 NXDOMAIN
  │
  ├─ 应答缓存命中 ──▶ 返回缓存结果
  │
  ├─ 转发模式 ──▶ 发送至上游（RD=1）──▶ 返回上游应答
  │
  └─ 递归模式 ──▶ 根提示迭代
                     │
                     ├─ 有 NS 委派 ──▶ 追踪 glue ──▶ 继续迭代
                     ├─ CNAME 链   ──▶ 重新解析目标
                     └─ 最终应答   ──▶ 缓存 + 返回
```

## 参考

- [RFC 1034](docs/rfc1034.txt) — Domain Names: Concepts and Facilities
- [RFC 1035](docs/rfc1035.txt) — Domain Names: Implementation and Specification
- [RFC 6891](docs/rfc6891.txt) — Extension Mechanisms for DNS (EDNS0)
