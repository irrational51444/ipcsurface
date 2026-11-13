# 和 Electronegativity 的对比（2026-11-13 实测）

Electronegativity 是 Doyensec 做的 Electron 安全检查工具，和本项目同域。这篇不吹谁赢，
只把两边**各自回答什么问题**摆清楚，附实测数字。

## 先说结论：两个工具问的不是同一件事

| | Electronegativity | ipcsurface |
| --- | --- | --- |
| 问的问题 | Electron **配置**有没有写错 | 有哪些 **IPC 通道**，每条能碰到什么危险 API |
| 输入 | `.asar` / 目录 / `.js` / `.html` | `.asar` |
| 输出 | 反模式清单（每条形如「这里用了 openExternal 但没校验」） | 能力面（通道 → API，带档位和位置） |
| 单位 | 一处配置 | 一条通道 / 一个 API |
| 能不能告诉你「这包有几条通道」 | 不能 | 能 |

**不重叠，互补。** 它管「门锁装得对不对」，我管「有哪些门、门后有什么」。

## 实测：obsidian.asar

同一份包，两边各跑一遍。

**Electronegativity（10 条发现）**

| check | 条数 | 严重度 | 置信度 |
| --- | --- | --- | --- |
| `OPEN_EXTERNAL_JS_CHECK` | 7 | MEDIUM | TENTATIVE |
| `PROTOCOL_HANDLER_JS_CHECK` | 2 | MEDIUM | TENTATIVE |
| `CSP_GLOBAL_CHECK` | 1 | LOW | CERTAIN |

耗时 13 秒。命中文件：`main.js` 8 处、`help.js` 1 处、`index.html` 1 处。

**ipcsurface（同一份包）**

| 项 | 数 |
| --- | --- |
| 通道 | 47 |
| sink 通道 | 24 |
| sink 结论（API 级） | 116 |
| 其中硬档（direct / name_confirmed / chain） | 25 |
| 其中软档（ambiguous / ast_only） | 91 |
| 没看清的（按原因分） | 394（全部是带命名空间的命令 id） |

耗时约 45 秒。

## 两边都在承认不确定，这是最值得记的一点

Electronegativity 10 条里有 **9 条标 TENTATIVE**——它自己说「这是反模式，但我不确定
在你的语境里算不算问题」。

ipcsurface 的 API 级精确率是 24%——我也在说「大部分软档结论你不该直接信」。

**两个工具都不敢拍胸脯。** 这不是巧合：静态分析本来就是这样。谁说自己 100% 准，
谁就是在骗人。

差别在于**怎么说清这件事**：

- 它用 `severity` + `confidence` 两个枚举，简单直接
- 我用五档来路 + 三段证据完整度 + 位置，能追到源码那一行

## 能不能合起来用

能，而且顺序有意义：

1. **先 ipcsurface**：看清这个包有哪些门、门后能碰到什么。这是「面」。
2. **再 Electronegativity**：看这些门的锁装得对不对。这是「点」。

反过来不行——不知道有哪些门，谈不上锁装得对不对。

## 复现

```bash
# Electronegativity
npm i @doyensec/electronegativity
node_modules/.bin/electronegativity -i app.asar -o out.csv -v false

# ipcsurface
python ipcsurface.py app.asar --summary      # 一页纸
python ipcsurface.py app.asar -o full.md     # 全量带证据
```

Electronegativity 扫 `.asar` 时会提示「Couldn't detect Electron version」——它要联网拉
版本列表，网络不通时按 v0.1.0 的默认值算。**结果是近似的**，这在它的输出里也说清了。
