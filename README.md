# ipcsurface

[![version](docs/badges/version.svg)](https://github.com/irrational51444/ipcsurface/releases)
[![tests](docs/badges/tests.svg)](tests/test_ipcsurface.py)
[![python](docs/badges/python.svg)](pyproject.toml)
[![license](docs/badges/license.svg)](LICENSE)

**把一个 Electron 应用的能力面压成一页纸。** 零依赖，只装 Python。当前 **0.64.0**。

`ipcsurface` 读一个 `.asar` 包（或 REA 的 Evidence JSON、一个 dll/exe），输出一份报告：有几条 IPC 通道、哪些名字是写死的、哪些是还原出来的、哪些只是长得像，以及**这份报告能信到什么程度**。

[English README](README.en.md) · [变更记录](CHANGELOG.md) · [示例靶场](examples/README.md)

---

## 它长什么样

拿一个真实的 Electron 应用跑：22,102 个文件、441 MB、**41 条通道**、4.6 秒。

![真实应用扫描输出](docs/img/case-real-scan.png)

一条命令出报告，md 和 json 同源：

![示例靶场](docs/img/case-fixture-run.png)

三道闸，本地和 CI 跑同一套：

![三道闸](docs/img/case-gates.png)

---

## 为什么不是「扫出通道数」就完事

同一份报告里的话，强度不是一样的。

| 这一层 | 这份真实报告里的数量 | 能证明什么 | 不能证明什么 |
| --- | --- | --- | --- |
| 写死的名字 | 11 条 | 源码里逐字写着，`file:line` 能回到原文复核 | 只覆盖写死的写法 |
| 靠还原才认出的 | 84 条 | 名字是从字符串池、常量里查出来的，出处还在源码里 | 查得出不等于它真是通道 |
| 名字是算出来的 | 0 条 | 知道这里在调用，名字不是写死的 | 名字是什么，算不出来 |
| 捞出来的候选 | 221 个（51 个它自己写的） | 这些字符串长得像通道名 | 长得像不等于就是 |
| 没看见的 | 未知 | 无 | 这条路看不见，不代表它不在 |

**这几层不可相加。** 同一个名字可能既被还原出来、又被运行时看到，两边都会算它。报告是给人做判断用的地图，不是判决书。

---

## 安装

```bash
pip install .
# 或者不装，直接用
python ipcsurface.py app.asar
```

要求 Python 3.9+，没有第三方依赖。

## 一分钟上手

```bash
# 1. 扫一个包，出 md
python ipcsurface.py app.asar -o report.md

# 2. 机器读的版本
python ipcsurface.py app.asar --format json -o report.json

# 3. 和上一版比，只看新冒出来的
python ipcsurface.py app.asar --baseline last.json -o diff.md

# 4. 挂 CI：有高危项就退出码 2
python ipcsurface.py app.asar --fail-on high -o report.md
```

自带靶场可以直接试（要先造包）：

```bash
cd examples && bash build.sh
python ipcsurface.py build/static-asar.asar -o report.md
```

---

## 这份报告的三条规矩

**一、未知写 `null`，不写 `0`。** 没看见不等于没有；`0` 会被人读成「确认没有」。

**二、证据只记来源，不下结论。** 每条通道都带 `evidence`，写清名字是从哪来的、强度多少。强度排的是**复核成本**，不是概率。

**三、消费方必须先校验 `schema`。** 现在十六位是 `ipcsurface/asar/10`；对不上就停下，别按字段在不在猜。

---

## 退出码

| 码 | 意思 | 该做什么 |
| --- | --- | --- |
| 0 | 成功，没有触发门禁 | 持久性看 stderr 的 `kind:` 行 |
| 1 | 输入有问题（文件不存在、不是 asar、参数不对） | 照提示修输入 |
| 2 | `--fail-on` 被触发 | 看报告里的可疑项 |
| 3 | 工具自己崩了 | 报 issue |
| 4 | 已写入但未持久化（目录 fsync 失败） | **文件已是新版，不要回滚、不要重跑** |

写失败时 stderr 会带一行 `kind: <类别>`，类别表在下面「错误词表」。

---

## 错误词表（机器可读）

输入侧：`file_missing`、`empty_input`、`encoding_invalid`、`json_truncated`、`json_malformed`、`shape_invalid`、`depth_exceeded`。

输出侧：`disk_full`、`permission_denied`、`short_write`、`replace_failed`、`symlink_target`、`write_failed`、`invalid_json_output`。

写入的持久性是三态：`yes` / `no` / `unknown`。`unknown` 出现在没有目录 fsync 能力的平台（Windows），退出码仍是 0，只在 stderr 说一次「无法确认持久性」。

---

## 质量怎么保证的

- **198 个用例**，只跑标准库：`python -m unittest discover -s tests`
- **冒烟 15 项**：真跑一遍 CLI 的所有入口
- **自查**：版本、schema、规则注册表、文档与实现一致性、工作区是否干净
- 三道闸一条命令：`bash scripts/verify.sh`，CI 也跑它

CI 同时验证「退出码能不能被下游当信号」：干净包必须退 0，有问题的包必须退 2，SARIF 能上传。

---

## 已知边界

- 字符串级粗扫，不建语法树；拼出来的、算出来的名字看不见。要准的走 REA Evidence。
- 沙箱、原生模块、运行时才装配的通道，静态看不到。
- Windows 上目录 fsync 不可用，`durable` 只能是 `unknown`；符号链接拒绝写、替换被占用这几条路径没有在真实环境跑过，写在 [CHANGELOG](CHANGELOG.md) 里。
- `adv-asar.asar` 这个对抗样本没有生成脚本，只在本地有，别的机器造不出来。

---

## 维护者自查（写给改它的人）

- 用例与文档的数字必须一致：198 个用例、冒烟 15 项，自查会核对。
- 全称断言的空集合防护是**按语义**判的：只建模真值只依赖集合自身属性的表达式；带集合语义但真值没建模的一律当危险报。
- 注释豁免要贴着断言写（中间不许夹语句），比率当前是 **2 / 3**（真空断言口径）——这个数涨了就是信号，不是背景音。

## 设计原则（写给以后改它的人）

1. 不把不知道报成知道。
2. 每个失败说清坏在哪、下一步做什么。
3. 纪律变成断言，不变成 README 里的一句话。
4. 测试要证明「该拦的拦住了」和「该放的放过了」，两条都要。

---

## 许可

MIT，见 [LICENSE](LICENSE)。
