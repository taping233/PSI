# D-PSI Protocol 3 真实部署版

这个目录实现“查询方有自己的集合”的 D-PSI 部署路径。它和 `protocol3` benchmark 的语义一致：委托方集合先形成一个随机交集编码 `R(x)`，查询方只在自己的集合上做根测试，返回满足 `R(a)=0` 的查询元素。

## 角色

- `cloud`：常驻云服务，只保存每个委托方的 cloud share。
- `query`：常驻查询方服务，保存 evaluator share 和查询方自己的集合。
- `client update`：某个委托方上传或替换自己的集合状态。
- `query-set update`：查询方上传或替换自己的查询集合。
- `result`：查询方拉取云端聚合份额，重构 `R(x)`，调用 C++/NTL/FLINT 后端对查询集合批量试根。

## 运行示例

先在项目根目录构建后端：

```bash
cmake --build build-rie --target dpsi_poly_backend --parallel
```

启动两个真实进程：

```bash
python3 deployments/dpsi_protocol3/deploy.py cloud \
  --host 127.0.0.1 --port 18801 \
  --state deploy_dpsi/cloud.json --token dev-token

python3 deployments/dpsi_protocol3/deploy.py query \
  --host 127.0.0.1 --port 18802 \
  --state deploy_dpsi/query.json \
  --cloud-url http://127.0.0.1:18801 --token dev-token
```

上传两个委托方集合和查询方集合：

```bash
python3 deployments/dpsi_protocol3/deploy.py client update \
  --party 1 --values '1 2 3 4' --degree-bound 4 \
  --cloud-url http://127.0.0.1:18801 \
  --query-url http://127.0.0.1:18802 --token dev-token

python3 deployments/dpsi_protocol3/deploy.py client update \
  --party 2 --values '3 4 5 6' --degree-bound 4 \
  --cloud-url http://127.0.0.1:18801 \
  --query-url http://127.0.0.1:18802 --token dev-token

python3 deployments/dpsi_protocol3/deploy.py query-set update \
  --values '0 3 4 9' \
  --query-url http://127.0.0.1:18802 --token dev-token
```

查询结果：

```bash
python3 deployments/dpsi_protocol3/deploy.py result \
  --query-url http://127.0.0.1:18802 --token dev-token
```

预期交集是 `[3, 4]`。如果把 party 2 更新为 `4 7 8`，结果会变成 `[4]`，不需要重启 cloud/query 服务。

## 实现边界

多项式构造、`omega_i p_i` 乘法和批量试根由 `build-rie/dpsi_poly_backend` 完成。Python 只负责 HTTP(S)、持久化和 JSON 编排。这个部署版是真实多进程/真实网络路径，但还不是论文的 FHE Beaver 预处理或完整 SPDZ 恶意安全实现。
