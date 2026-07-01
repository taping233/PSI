# PSI

这个仓库包含两部分代码：

- `PSI-main/`：仓库原有 PSI 代码。
- `direct_fft_no_bucket_plain32/`：新增的 D-PSI / 第三方 PSI 实验与部署实现。

`direct_fft_no_bucket_plain32/` 里包含：

- 单机高性能 benchmark：Protocol 3、第三方 Method 2、通信模型、TLS/RSA/AES 计量。
- `deployments/dpsi_protocol3/`：D-PSI 真实多进程部署，查询方有自己的集合，结果通过批量试根得到。
- `deployments/third_party_method2/`：第三方无输入 PSI 真实多进程部署，结果通过 `gcd(R1,R2)` 和提根得到。
- `src/dpsi_poly_backend.cpp`：部署工具使用的 C++/NTL/FLINT 多项式后端，负责份额生成、GCD、提根和批量试根。

详细构建、运行和安全边界说明见 `direct_fft_no_bucket_plain32/README.md`。
