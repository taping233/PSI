# direct_fft_no_bucket_plain32：D-PSI / 第三方 PSI 实验与部署实现

本目录包含两类实现：

1. **高性能单机 benchmark**：`build-rie/psi_direct_fft_no_bucket`，用于复现实验、计时、通信估计和论文步骤对齐。
2. **真实多进程部署工具**：`deployments/` 和 `tools/dpsi_deploy.py`，用于把 cloud、query、client 拆成不同进程，通过 HTTP(S) 交换份额并支持动态更新。

当前支持两种协议语义：

- **D-PSI / Protocol 3**：查询方有自己的集合，最后对查询集合做试根。
- **第三方无输入 PSI / Method 2**：查询方没有集合，运行两轮 RIE，计算 `gcd(R1,R2)` 后提取根。

## 目录结构

```text
src/main.c                         单机 benchmark 主程序
src/dpsi_poly_backend.cpp          部署工具使用的 C++/NTL/FLINT 多项式后端
tools/run_bench.py                 批量实验脚本
tools/dpsi_deploy.py               第三方 Method 2 部署工具原始入口
deployments/dpsi_protocol3/        D-PSI 查询方有集合的真实部署目录
deployments/third_party_method2/   第三方无输入 Method 2 的真实部署目录
docs/PAPER_ALIGNMENT.md            与论文步骤的对齐说明
```

## 依赖

需要 Linux 环境，并安装：

- CMake
- GCC/G++
- GMP / GMPXX
- FLINT
- NTL
- OpenSSL
- OpenMP
- Python 3.10+

## 构建

```bash
cmake -S . -B build-rie -DCMAKE_BUILD_TYPE=Release
cmake --build build-rie --parallel
```

只构建部署工具使用的多项式后端：

```bash
cmake --build build-rie --target dpsi_poly_backend --parallel
```

## 单机 benchmark 模式

### D-PSI / Protocol 3

查询方有自己的集合。程序重构一个 RIE 多项式 `R(x)`，然后只测试查询方集合中的元素是否为根：

```bash
./build-rie/psi_direct_fft_no_bucket \
  --mode protocol3 --clients 2 --exp 8 --scenario half
```

### 第三方无输入 / Method 2

查询方没有集合。程序运行两轮独立 RIE，计算：

```text
I(x) = gcd(R1(x), R2(x))
```

然后提取 `I(x)` 的线性根作为委托方交集：

```bash
./build-rie/psi_direct_fft_no_bucket \
  --mode protocol3-method2 --clients 2 --exp 8 --scenario half
```

旧别名 `third-party-method2` 仍可用。

## 真实部署模式

两个部署目录是分开的：

- `deployments/dpsi_protocol3/`：D-PSI，查询方有集合，结果是查询集合中满足 `R(a)=0` 的元素。
- `deployments/third_party_method2/`：纯第三方 PSI，查询方没有集合，结果是 `roots(gcd(R1,R2))`。

二者都是真实多进程部署：cloud 和 query 是常驻服务，client 通过 HTTP(S) 上传或替换自己的份额。再次执行 `client update` 就是动态更新，不需要重启服务。

详细命令见两个目录各自的 `README.md`。

## 部署后端

`src/dpsi_poly_backend.cpp` 编译出的 `build-rie/dpsi_poly_backend` 提供三个子命令：

```bash
dpsi_poly_backend share   # 构造 p_i(x)，采样 omega_i，计算 omega_i p_i 并拆份额
dpsi_poly_backend eval    # 对查询集合做 FLINT 快速多点求值/试根
dpsi_poly_backend roots   # 对 R1/R2 做 NTL GCD，并用 FLINT 提取线性根
```

因此部署工具里的 Python 不负责重型多项式计算，只负责网络、持久化和 JSON 编排。

## 通信时间模型

单机 benchmark 默认输出 `RIE_TRANSPORT`，通信时间估计使用保存的知乎长连接模型：

```text
WAN: transport_time = 0.538 + 0.116 * communication_mb   # x > 40 MB
LAN: transport_time = 0.024 + 0.004 * communication_mb   # x > 10 MB
```

可用参数切换：

```bash
--transport-model zhihu-linear|latency-bandwidth
--transport-profile lan|wan|custom
--transport tcp-tls
```

`--transport tcp-tls` 会在单机 benchmark 里打开 loopback TCP/TLS RPC，用于测量真实 OpenSSL 握手和长连接传输开销。

## 当前实现边界

已经实现：

- Protocol 3 的 RIE 流程和查询方试根。
- Method 2 的两轮 RIE、NTL GCD、FLINT 提根。
- AES-256-GCM、RSA-OAEP-SHA256、loopback TLS benchmark plumbing。
- 两种真实多进程部署目录。
- 动态更新：替换或删除某个 party 的持久化份额。
- C++/NTL/FLINT 部署后端。

仍未实现完整论文安全语义：

- FHE 分布式 Beaver triple 生成。
- 完整 SPDZ authenticated shares / arithmetic MAC。
- hash-tag 编码和 hash-table/binning 优化。
- 生产级 PKI、每个 party 的身份体系、重放防护和审计。

所以当前代码适合作为论文协议结构、性能实验和部署原型；如果要声称完整 malicious security，还需要继续补 FHE/SPDZ 层。

## 正确性与效率检查

已验证的小规模动态部署：

- D-PSI：party1 `{1,2,3,4}`，party2 `{3,4,5,6}`，query `{0,3,4,9}`，结果 `[3,4]`；更新 party2 为 `{4,7,8}` 后结果 `[4]`。
- 第三方 Method 2：party1 `{1,2,3,4}`，party2 `{3,4,5,6}`，结果 `[3,4]`；更新 party2 为 `{4,7,8}` 后结果 `[4]`。

1024 元素规模的后端微基准结果大致为：

```text
share 每个 party 两轮：约 7-9 ms
D-PSI eval 批量试根：约 8 ms
Method 2 roots(GCD+提根)：约 365 ms，交集度 512
```
