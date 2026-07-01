# PSI：D-PSI 与第三方 PSI 的可部署实现

本仓库围绕论文中的委托多方 PSI（Delegated PSI, D-PSI）思路，整理出一个可编译、可测试、可真实多进程部署的实现。当前主代码位于 `direct_fft_no_bucket_plain32/`，旧的原始代码目录已经移除，避免两个版本并存造成入口和协议语义混淆。

仓库现在重点支持两类场景：

1. **D-PSI / Protocol 3**：查询方有自己的集合。云端和多个客户端先协作生成 RIE 多项式，查询方只在自己的候选集合上做多项式求值，命中零值即为交集元素。
2. **第三方无输入 PSI / Method 2**：第三方查询方没有输入集合。系统运行两轮独立 RIE，第三方计算两个 RIE 多项式的 `gcd`，再从最大公因式中提取根，得到多个客户端集合的交集。

## 和论文的关系

论文中的核心抽象可以理解为三类角色：

- `P_i`：持有隐私集合的客户端。
- `C`：云端，负责聚合份额和恢复被随机化后的多项式结构。
- `P_{N+1}` / third party：查询方或第三方，负责最终求交集。

本仓库实现的主线是论文里的 RIE（Randomized Interpolation Encodings）路径。对每个客户端集合构造集合多项式 `p_i(x)`，再通过随机权重组合成：

```text
R(x) = sum_i omega_i(x) * p_i(x)
```

在 `Protocol 3` 中，查询方已有候选集合，只需要检查候选点是否为 `R(x)` 的根。在 `Method 2` 中，第三方没有候选集合，因此需要两轮随机化结果 `R1(x)` 和 `R2(x)`，通过：

```text
I(x) = gcd(R1(x), R2(x))
```

恢复共同根。实际部署工具中的多项式构造、GCD、roots、multipoint evaluation 已经改为调用现有 C++/NTL/FLINT 后端，不再在 Python client side 手写这些代数运算。

## 目录结构

```text
direct_fft_no_bucket_plain32/
  src/
    main.c                         单机 benchmark 主程序
    dpsi_poly_backend.cpp          部署工具使用的 C++/NTL/FLINT 多项式后端
  deployments/
    dpsi_protocol3/                D-PSI / Protocol 3 真实多进程部署
    third_party_method2/           第三方无输入 Method 2 真实多进程部署
  tools/
    run_bench.py                   批量 benchmark 脚本
    dpsi_deploy.py                 早期 Method 2 部署入口，保留作兼容
  docs/
    PAPER_ALIGNMENT.md             代码和论文步骤的对齐说明
  README.md                        主实现手册
```

## 环境依赖

推荐在 Linux 环境构建和运行，需要安装：

- `cmake`
- `gcc` / `g++`
- `gmp` / `gmpxx`
- `flint`
- `ntl`
- `openssl`
- `openmp`
- `python3`

## 快速构建

```bash
cd direct_fft_no_bucket_plain32
cmake -S . -B build-rie -DCMAKE_BUILD_TYPE=Release
cmake --build build-rie --parallel
```

构建完成后会得到两个主要可执行文件：

- `build-rie/psi_direct_fft_no_bucket`：单机 benchmark 入口。
- `build-rie/dpsi_poly_backend`：真实部署工具调用的 C++ 多项式后端。

## 模式一：D-PSI / Protocol 3

该模式适合“查询方也有集合”的场景。查询方并不恢复完整交集空间，只对自己的集合做试根。

单机 benchmark：

```bash
./build-rie/psi_direct_fft_no_bucket \
  --mode protocol3 \
  --clients 2 \
  --exp 8 \
  --scenario half
```

真实多进程部署目录：

```text
direct_fft_no_bucket_plain32/deployments/dpsi_protocol3/
```

典型启动方式：

```bash
# 终端 1：cloud
python3 deploy.py cloud --host 127.0.0.1 --port 9000 --clients 2

# 终端 2：party 1
python3 deploy.py client --party-id 1 --cloud-url http://127.0.0.1:9000 \
  --set-file party1.txt

# 终端 3：party 2
python3 deploy.py client --party-id 2 --cloud-url http://127.0.0.1:9000 \
  --set-file party2.txt

# 终端 4：query
python3 deploy.py query --cloud-url http://127.0.0.1:9000 \
  --set-file query.txt --out result.json
```

该部署支持客户端动态更新集合。客户端重新提交后，cloud 生成新 epoch，query 再次运行即可得到更新后的结果。

## 模式二：第三方无输入 PSI / Method 2

该模式适合“第三方没有集合，只想得到多个客户端交集”的场景。它不是在查询集合上试根，而是运行两轮 RIE 并对两个结果做 `gcd`，最后提取共同根。

单机 benchmark：

```bash
./build-rie/psi_direct_fft_no_bucket \
  --mode protocol3-method2 \
  --clients 2 \
  --exp 8 \
  --scenario half
```

真实多进程部署目录：

```text
direct_fft_no_bucket_plain32/deployments/third_party_method2/
```

典型启动方式：

```bash
# 终端 1：cloud
python3 deploy.py cloud --host 127.0.0.1 --port 9100 --clients 2

# 终端 2：party 1
python3 deploy.py client --party-id 1 --cloud-url http://127.0.0.1:9100 \
  --set-file party1.txt

# 终端 3：party 2
python3 deploy.py client --party-id 2 --cloud-url http://127.0.0.1:9100 \
  --set-file party2.txt

# 终端 4：third party
python3 deploy.py third-party --cloud-url http://127.0.0.1:9100 \
  --out result.json
```

## C++ 多项式后端

部署脚本会调用 `dpsi_poly_backend` 完成以下操作：

- `share`：基于客户端集合生成 RIE 份额。
- `eval`：对查询集合做 multipoint evaluation，用于 D-PSI / Protocol 3。
- `roots`：计算 `gcd` 并用 FLINT 提取根，用于第三方 Method 2。

这样做的原因是多项式 GCD、求根和批量求值是协议中的重计算路径，放在 C++/NTL/FLINT 中更接近论文实现和真实性能；Python 只负责进程编排、HTTP 通信、epoch 状态和 JSON 输入输出。

## 已验证内容

当前版本已经做过以下验证：

- CMake Release 构建通过。
- `dpsi_poly_backend` 的 `eval` 和 `roots` 子命令通过小例子验证。
- D-PSI / Protocol 3 多进程部署可以得到交集，并能在客户端更新后得到新结果。
- 第三方无输入 Method 2 多进程部署可以通过 `gcd + roots` 得到交集，并能在客户端更新后得到新结果。
- Python 部署脚本通过 `py_compile` 语法检查。

## 当前边界

这个仓库已经把论文协议中的主要代数路径落到可运行代码，但仍不是生产级隐私系统。当前边界包括：

- 真实部署使用 HTTP/JSON 做演示传输，生产环境需要 TLS、鉴权、重放保护和密钥管理。
- 论文中更完整的 FHE / Beaver triple / SPDZ 安全执行链路没有完整工程化。
- 当前集合元素按整数域处理，没有加入完整的哈希到域、分桶和大规模域编码策略。
- 单机 benchmark 和真实部署工具服务于不同目标：前者用于实验计时，后者用于验证角色拆分、动态更新和协议流程。

更详细的构建、部署、后端命令和论文对齐说明请看 `direct_fft_no_bucket_plain32/README.md` 与 `direct_fft_no_bucket_plain32/docs/PAPER_ALIGNMENT.md`。
