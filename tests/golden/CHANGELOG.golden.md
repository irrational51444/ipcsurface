# 金标准快照变更记录

格式固定，由 scripts/make_golden.py 写入：

    ## YYYY-MM-DD HH:MM
    - 变了的字段：a, b
    - 理由：...

最新的追加在文件末尾。人工不要改格式，脚本解析靠它。

## 2026-11-09 00:48

- 变了的字段：confidence, fingerprint
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 00:49

- 变了的字段：fingerprint
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:02

- 变了的字段：sites
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:02

- 变了的字段：fingerprint
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:03

- 变了的字段：confidence_semantics
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:13

- 变了的字段：fingerprint
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:20

- 变了的字段：fingerprint
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:42

- 变了的字段：evidence
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:43

- 变了的字段：fingerprint
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:53

- 变了的字段：evidence
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:54

- 变了的字段：content_digest
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:54

- 变了的字段：content_digest
- 理由：0.71.0 报告加 archive_merkle 与 content_digest、evidence 带 where_all，快照跟着更新

## 2026-11-09 01:54

- 变了的字段：content_digest
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:55

- 变了的字段：content_digest
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:55

- 变了的字段：content_digest
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:55

- 变了的字段：content_digest
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:55

- 变了的字段：content_digest
- 理由：试试内容没变时会怎么说

## 2026-11-09 01:55

- 变了的字段：content_digest
- 理由：内容其实没变，确认这一版会怎么说 reason 未写进

## 2026-11-09 01:55

- 变了的字段：content_digest
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 01:55

- 变了的字段：content_digest, fingerprint
- 理由：抹掉指纹里和路径相关的字段，快照才能稳定

## 2026-11-09 01:56

- 变了的字段：fingerprint
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 02:13

- 变了的字段：fingerprint
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 13:56

- 变了的字段：content_digest, fingerprint
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 14:28

- 变了的字段：confidence_semantics, fingerprint, schema
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 14:31

- 变了的字段：fingerprint
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 15:09

- 变了的字段：fingerprint, schema
- 理由：0.75.0 升 schema 到 asar/12（enumerated 强度分档 + enum_proof 字段）

## 2026-11-09 16:08

- 变了的字段：fingerprint
- 理由：0.76.0 版本号变了，金标准里的 version 字段跟着更新

## 2026-11-09 17:02

- 变了的字段：fingerprint
- 理由：0.77.0 版本号变了，金标准里的 version 字段跟着更新

## 2026-11-09 17:12

- 变了的字段：confidence, fingerprint, schema
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-09 17:13

- 变了的字段：fingerprint
- 理由：0.78.0 版本号变了，金标准里 version 跟着走

## 2026-11-09 17:31

- 变了的字段：evidence, fingerprint, schema
- 理由：0.79.0 升 schema 到 asar/14：evidence 新增 capability 字段

## 2026-11-09 17:36

- 变了的字段：fingerprint
- 理由：0.80.0 版本号变了，金标准 version 跟着走

## 2026-11-10 01:54

- 变了的字段：fingerprint, schema
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-10 13:40

- 变了的字段：channel_sinks
- 理由：这次内容其实没有变化，只是验证提示语

## 2026-11-10 13:48

- 变了的字段：channel_unattributed
- 理由：报告新增 channel_unattributed：把解不出来的注册点数报出来，空档要有数字

## 2026-11-10 13:51

- 变了的字段：channel_unattributed_samples
- 理由：新增 channel_unattributed_samples：把卡住的表达式带回来，方便判断该不该往下钻

## 2026-11-10 13:55

- 变了的字段：channel_names_recovered
- 理由：新增 channel_names_recovered：常量键反推的结果，唯一才补、多值列歧义

## 2026-11-10 14:13

- 变了的字段：channel_dynamic_in_deps
- 理由：把第三方依赖里的动态注册单独计一档，和应用自己的空档分开

## 2026-11-10 16:20

- 变了的字段：channel_tainted
- 理由：新增 channel_tainted：第二条口径，外部输入能到危险参数

## 2026-11-10 16:22

- 变了的字段：channel_sink_paths
- 理由：新增 channel_sink_paths：每条危险调用的来路写清楚，少让人回原文找

## 2026-11-10 16:37

- 变了的字段：channel_sinks_ast
- 理由：新增 channel_sinks_ast：语法树口径的可达性（成员调用、回调、别名）

## 2026-11-10 16:47

- 变了的字段：fingerprint, schema
- 理由：升版 0.82.0：schema 到 asar/16，报告新增树口径与污点列

## 2026-11-10 19:43

- 变了的字段：channel_sinks_ambiguous
- 理由：新增 channel_sinks_ambiguous：经过同名多义链的结论单独标出来

## 2026-11-11 00:33

- 变了的字段：fingerprint, schema
- 理由：升版 0.83.0：schema 到 asar/17（新增 channel_sinks_ambiguous 等键）

## 2026-11-11 02:18

- 变了的字段：fingerprint
- 理由：升版 0.84.0：版本号由主模块注入报告层

## 2026-11-11 18:10

- 变了的字段：attack_surface, schema
- 理由：P1-5 新增能力面字段 attack_surface，schema 升到 asar/18

## 2026-11-11 19:13

- 变了的字段：native_imports, schema
- 理由：新增 native_imports 顶层键，schema 升 19

## 2026-11-11 21:00

- 变了的字段：fingerprint, schema
- 理由：新增 channel_sink_tiers：每条危险 API 的来路可信度档，schema 升到 asar/20

## 2026-11-12 09:20

- 变了的字段：channel_profiles, schema
- 理由：新增 channel_profiles（每条通道的能力标签+代码位置+证据来源），schema 升 21

## 2026-11-12 09:23

- 变了的字段：fingerprint
- 理由：修指纹硬编码：schema 从写死的 asar/17 改成注入的 SCHEMA_VERSION，指纹里的 schema 不再漂

## 2026-11-12 13:28

- 变了的字段：fingerprint
- 理由：0.87.0 版本号 + jsevents 模块

## 2026-11-12 13:32

- 变了的字段：fingerprint
- 理由：0.88.0 版本号

## 2026-11-12 13:37

- 变了的字段：fingerprint
- 理由：0.89.0 版本号

## 2026-11-12 13:49

- 变了的字段：fingerprint
- 理由：0.90.0 版本号

## 2026-11-12 14:01

- 变了的字段：fingerprint
- 理由：0.91.0 版本号

## 2026-11-12 14:06

- 变了的字段：fingerprint
- 理由：0.92.0 版本号

## 2026-11-12 14:13

- 变了的字段：fingerprint
- 理由：0.93.0 版本号

## 2026-11-12 14:22

- 变了的字段：fingerprint
- 理由：0.94.0 版本号

## 2026-11-12 14:29

- 变了的字段：fingerprint
- 理由：0.95.0 版本号

## 2026-11-12 14:49

- 变了的字段：fingerprint
- 理由：0.96.0 版本号

## 2026-11-12 15:04

- 变了的字段：fingerprint, schema
- 理由：schema 22：软档不再进结论，单独 channel_sinks_borrowed

## 2026-11-12 15:08

- 变了的字段：fingerprint
- 理由：0.97.0 版本号

## 2026-11-12 15:18

- 变了的字段：fingerprint, schema
- 理由：schema 23：全档位照报 + channel_sink_evidence

## 2026-11-12 15:21

- 变了的字段：fingerprint
- 理由：0.98.0 版本号

## 2026-11-12 16:10

- 变了的字段：fingerprint
- 理由：0.99.0 版本号

## 2026-11-12 17:06

- 变了的字段：fingerprint
- 理由：0.100.0 版本号

## 2026-11-12 23:37

- 变了的字段：fingerprint
- 理由：0.101.0 版本号

## 2026-11-12 23:45

- 变了的字段：fingerprint, schema, unresolved_reasons
- 理由：0.102.0 unresolved_reasons

## 2026-11-13 00:14

- 变了的字段：unresolved_reasons
- 理由：dynamic-registration 归因

## 2026-11-13 00:15

- 变了的字段：fingerprint
- 理由：unresolved_reasons 新增 dynamic-registration 桶：名字是变量的 IPC 注册从静默跳过改成记进归因，带 at/expr 样本。下游读 unresolved_reasons 的消费方会多看到一个 key，schema 号不变（24 已含容器）
