# 实时事件流（P1：EventBus + JSONL）

设计来自《ipcsurface 实时报告系统设计》，这里只落 **P1**：把扫描过程录成一条
可回放、可对账的事件流。没有 TUI、没有 Web、没有预警引擎——那些是 P2 往后。

## 定位

现有报告回答「审计结束后，结论是什么」。事件流回答「审计进行中，工具在做什么」。
两者不是替代关系，是同一份证据的两种时态。

**硬约束**：事件流里的每一条发现，都必须能在最终报告里找到对应条目。
`lifecycle.done` 的统计字段和报告顶层统计**逐项相等**——这条写进测试，
对不上就是设计坏了，不是「数据有点小误差」。

## 用法

```bash
python ipcsurface.py app.asar --format json -o report.json --events-out events.jsonl
```

不加 `--events-out` 时，`bus` 是 `None`，每个 emit 点第一行就返回——**零开销**，
输出字节级不变。

## 事件信封

```json
{
  "schema": "ipcsurface/event/1",
  "seq": 42,
  "ts": "2026-11-12T05:23:58.333Z",
  "scan_id": "sha256:3a349274...",
  "phase": "coarse",
  "kind": "discovery",
  "payload": {"entity": "channel", "name": "app/saveFile", "tier": null}
}
```

- `seq` 单调递增，SSE 重连时用它做 `Last-Event-ID`
- `scan_id` = **输入文件的 sha256**，和报告 `fingerprint.input_sha256` 同一个值，
  两边能直接对上（不是为了好看才这么选的）
- `phase`：`coarse` / `tree` / `precise` / `probe` / `report`

## 事件类别

| kind | 何时发 | 可丢 |
| --- | --- | --- |
| `lifecycle` | 扫开始 / 扫结束 | 否 |
| `progress` | 每 100 个文件 | **是**（高频，可采样） |
| `discovery` | 每认出一条通道 | 否 |
| `evidence` | 证据升级/降级（P4 才填） | 否 |
| `warning` | 命中预警规则（P4 才填） | 否 |
| `unresolved` | 归因到盲区（P2 才填） | 否 |
| `stats` | 阶段性统计 | **是**（可覆盖） |

## 队列与背压

- 队列上限 10 000 条
- 溢出时**只丢 `progress`/`stats`**；不可丢的事件碰上满队列，会挤掉一条可丢事件腾位置
- 写了多少、丢了多少，`bus.stats()` 里都有数

## 对账

```python
import jsevents, json
report = json.load(open('report.json', encoding='utf-8'))
problems = jsevents.diff_summary('events.jsonl', report)
# [] 表示一致；非空就是事件流和报告对不上，得查
```

`report_summary()` 用和 `analyse_asar` 完全一样的口径，从报告里重算
`channels` / `sinks` / `by_tier` / `unresolved` 四个数，再和事件流末条比。

## 实测（2026-11-12，obsidian.asar 26.8 MB）

```
耗时：不带事件 4.77s / 带事件 4.79s（3 次中位数）
开销：0.5%
事件：54 条，14 KB
  lifecycle.start ×1 → progress ×4 → discovery ×47 → stats ×1 → lifecycle.done ×1
对账：channels 47 / sinks 116 / by_tier {chain 15, name_confirmed 9, ast_only 50, ambiguous 41, direct 1}
      / unresolved 0 —— 事件流和报告逐项一致
```

设计文档里 P1 的要求是「448 MB 包实时开销 < 2%」和「事件流末条统计 == 报告统计」。
第一个在 26.8 MB 上测到 0.5%，**448 MB 上还没测**——这是 P1 交接时要说清的缺口。

## 还没做的（别读成已做）

- `evidence` / `warning` / `unresolved` 三类事件现在是空的：P1 只录 lifecycle/progress/discovery/stats
- 归因枚举（`lexer-unrecognized-char` 等 11 个）**代码里还没有**，要先落地
- 没有 TUI、没有 SSE、没有 Web、没有回放 CLI
- `--events-out` 会多读一遍输入文件算 sha256，这是开实时才付的代价
