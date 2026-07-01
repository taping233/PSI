# 第三方无输入 Method 2 真实部署版

这个目录实现“查询方没有输入集合”的第三方 PSI 部署路径。它和 `protocol3-method2` benchmark 的语义一致：每个委托方生成两轮独立 RIE 份额，查询方重构 `R1/R2` 后计算 `gcd(R1,R2)`，再提取线性根作为委托方交集。

## 角色

- `cloud`：常驻云服务，只保存每个委托方两轮 cloud shares。
- `query`：常驻第三方查询服务，只保存 evaluator shares。
- `client update`：某个委托方上传或替换自己的两轮状态。
- `result`：第三方查询服务拉取云端聚合份额，重构 `R1/R2`，调用 C++/NTL/FLINT 后端做 GCD 和提根。

## 运行示例

```bash
cmake --build build-rie --target dpsi_poly_backend --parallel

python3 deployments/third_party_method2/deploy.py cloud \
  --host 127.0.0.1 --port 18811 \
  --state deploy_tp/cloud.json --token dev-token

python3 deployments/third_party_method2/deploy.py query \
  --host 127.0.0.1 --port 18812 \
  --state deploy_tp/query.json \
  --cloud-url http://127.0.0.1:18811 --token dev-token
```

上传两个委托方集合并查询：

```bash
python3 deployments/third_party_method2/deploy.py client update \
  --party 1 --values '1 2 3 4' --degree-bound 4 \
  --cloud-url http://127.0.0.1:18811 \
  --query-url http://127.0.0.1:18812 --token dev-token

python3 deployments/third_party_method2/deploy.py client update \
  --party 2 --values '3 4 5 6' --degree-bound 4 \
  --cloud-url http://127.0.0.1:18811 \
  --query-url http://127.0.0.1:18812 --token dev-token

python3 deployments/third_party_method2/deploy.py result \
  --query-url http://127.0.0.1:18812 --token dev-token
```

预期交集是 `[3, 4]`。再次对同一个 `party` 执行 `client update` 就是动态替换；执行 `client delete` 可删除该委托方。

## 实现边界

`deploy.py` 默认调用 `build-rie/dpsi_poly_backend share` 生成两轮份额，调用 `build-rie/dpsi_poly_backend roots` 做 NTL GCD 和 FLINT 线性根提取。该路径是真实多进程/真实网络部署，但委托方本地计算 `omega_i p_i` 后再拆份额，因此不等于论文完整 FHE Beaver 预处理或完整 SPDZ 恶意安全版本。
