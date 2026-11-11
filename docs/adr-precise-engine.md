# ADR：precise 双引擎（tree-sitter 精查层）

- 状态：已提议（Proposed）
- 日期：2026-11-11
- 关联：路线图 P1-7；`docs/parser-decision.md`（手写解析器的边界与翻案条件）

## 背景

现在只有一条「粗扫」路径：手写词法 + 手写语法树，零依赖。它能认出大部分通道，
但有两处到顶了：

1. **解析器脱轨**是未知节点里最大头（四包 0.95%–6.48%），打补丁越来越贵；
2. **跨文件调用跟不过去**——抖音 22 条通道的 sink 全是空的，因为 handler 把活
   委托给跨文件的类方法（`this._getStaticSetting()`），粗扫的树只在一个文件里连边。

路线图给的答案是「双引擎」：粗扫保持默认零依赖（内核要求的入口），新增
`ipcsurface[precise]` opt-in，用 tree-sitter + 跨函数调用图 + 摘要式污点。

## 决定

加一个 **opt-in 的精查层**，不是替换，是并列：

| | 粗扫（默认，现在就有） | precise（opt-in） |
| --- | --- | --- |
| 入口 | `ipcsurface app.asar` | `ipcsurface --precise app.asar` |
| 依赖 | 零（纯标准库） | tree-sitter + 语言绑定（装在 `ipcsurface[precise]` extra） |
| 解析 | 手写词法 + 手写树 | tree-sitter（js/ts grammar） |
| 调用图 | 单文件 | 跨文件 |
| 污点 | 单文件可达 | 摘要式（函数摘要 + 跨文件传播） |
| 产出 | 同一份报告的证据分层 | 第三列结果，标「更强一档证据」，**永不叫确认** |

关键约束（不可稀释的内核）：

- precise 的结论进**同一证据分层**，只是 `strength` 更高一档，标签是「更强一档证据」，
  不是「确认」；
- 默认路径零依赖不变——precise 装不上，粗扫照跑，绝不让 opt-in 反过来卡死入口；
- 主线 Markdown 一页纸不变——precise 的新列只进计数+样本，全量进 JSON。

## 为什么是 opt-in 而不是替换

1. **零依赖是入口条件**。粗扫一条命令就能用，是「别人 clone 下来就能复现」的底线。
   tree-sitter 引入原生编译和网络装包，把它做成默认会破坏这条；
2. **数字要能对照**。粗扫和 precise 跑同一批包，差异本身是信号（哪里是粗扫漏的、
   哪里是 precise 多报的），替换掉粗扫就丢了这面镜子；
3. **翻案成本可控**。precise 是隔离的一层，做得不好可以整层回滚，不动粗扫。

## 翻案条件（什么时候回到单一引擎）

- 手写解析器在四包上持续 >10% 未知节点率，或全局连续三个版本上升（见
  `docs/parser-decision.md` 的同一组条件）；
- precise 在 benchmark 上证明「补上的跨文件 sink 全部为真」（precision 不掉）——
  这时才考虑默认开 precise，而不是 opt-in。

## 性能预算

- precise 不是实时路径，允许慢：**单包 ≤ 10× 粗扫耗时**是预算上限；
- 超出预算，先砍「摘要式污点」的传播深度，再砍跨文件边数，绝不用并行换正确率。

## 回滚点

- precise 全部圈在 `--precise` 分支和 `precise/` 子模块里；
- `git revert` 掉 precise 相关提交，粗扫路径零变化（这是验收标准里的一条）。

## 待办（本 ADR 之后）

1. ~~确认 tree-sitter 的 js grammar 与手写树在四包上的未知节点率对比~~ —— Obsidian main.js 实测
   （见下）；
2. 跨文件调用图的最小可行版：先只连「同一 asar 内、显式 require/import 的模块」；
3. 摘要式污点的第一版：函数级摘要（入口参数 → 是否触危险 API），不做到字段级。

## 实测：手写树 vs tree-sitter（Obsidian main.js，203 KB）

| | 节点数 | 未知/ERROR | 耗时 |
| --- | --- | --- | --- |
| 手写 jsast | 18,317 | 142（0.78%） | 0.09s |
| tree-sitter | 65,274 | 0（0.00%） | 0.05s |

tree-sitter 在同一份真文件上：未知节点 0、节点数多 3.5 倍（树更密，跨文件边有得连）、
还更快。这坐实了「手写解析器到顶、precise 层该上 tree-sitter」的判断，不是换个花哨
工具，是有实测差值的。

（tree-sitter 0.26.1 + tree-sitter-javascript 0.25.0 有预编译 wheel，`pip install` 直接装，
不进默认路径——precise 是 opt-in extra。）

## 验收

- ADR 过审（本文档）；
- precise 在至少一个真包上给出第三列结果，且粗扫默认路径零变化（同一批包、同一数字）。
