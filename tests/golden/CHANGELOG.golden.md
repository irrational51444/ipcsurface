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

## 2026-11-13 00:32

- 变了的字段：unresolved_reasons
- 理由：unresolved_reasons 新增 cross-file-depth-exceeded：调用链撞 max_depth=4 的条数从静默变成单独计数，带 通道/API/跳数 样本。下游会多看到一个 key，schema 24 不变

## 2026-11-13 00:32

- 变了的字段：fingerprint
- 理由：0.104.0 版本号与 CHANGELOG

## 2026-11-13 14:53

- 变了的字段：fingerprint
- 理由：0.105.0 版本号：render_summary 新增，不影响报告快照字段，只变 fingerprint 里的 version

## 2026-11-13 15:08

- 变了的字段：unresolved_reasons
- 理由：unresolved_reasons 新增 harvested-namespaced：obsidian 394 条带冒号候选从 harvested-only 拆出来（它 47 条真通道全不带冒号，那是 command id）；dsh 真通道全带冒号，所以判据不成立、不拆

## 2026-11-13 15:09

- 变了的字段：fingerprint
- 理由：0.106.0 版本号：md 提示段措辞改了，unresolved_reasons 不变

## 2026-11-13 15:21

- 变了的字段：fingerprint
- 理由：0.107.0 版本号：fingerprint 里的 version 变，字段不变

## 2026-11-13 15:28

- 变了的字段：fingerprint
- 理由：0.108.0 常量折叠：jsparse 加 fold_literal_concat，纯字面量拼接的注册名能折出来；报告字段不变

## 2026-11-13 15:39

- 变了的字段：fingerprint, unresolved_reasons
- 理由：0.109.0 新增 encrypted-payload 归因桶与 detect_encrypted_payload；靶场没有大块 hex 所以计数为 0，报告多一个 key

## 2026-11-13 15:46

- 变了的字段：fingerprint
- 理由：0.110.0 module_aliases 支持解构式 require，跨文件直接调用能跟下去；target 靶场里有解构 require 的话 channel_sinks 会变多

## 2026-11-13 15:55

- 变了的字段：fingerprint
- 理由：0.111.0 版本号：fingerprint 里的 version 变

## 2026-11-13 16:01

- 变了的字段：fingerprint
- 理由：0.112.0 纯文档与版本号：known-wrong 记了 depth 实测，报告字段不变

## 2026-11-13 16:09

- 变了的字段：fingerprint
- 理由：0.113.0 新增 docs/comparison.md 与 CHANGELOG 里版本号变；报告字段不变

## 2026-11-13 16:21

- 变了的字段：fingerprint
- 理由：0.114.0 SARIF 规则 id 改成固定值 + 新增 terminology 文档；报告快照字段不变，fingerprint 里的 version 变

## 2026-11-13 16:37

- 变了的字段：fingerprint
- 理由：0.115.0 新增 docs/audit-obsidian.md 与 terminology 里 direct 定义改准；报告字段不变

## 2026-11-13 17:10

- 变了的字段：fingerprint
- 理由：0.116.0 audit-obsidian.md 补成完整版（25 条全覆盖）+ CHANGELOG；报告字段不变

## 2026-11-13 17:13

- 变了的字段：fingerprint
- 理由：0.117.0 新增交付型审计报告模板 docs/audit-report-template.md；报告字段不变

## 2026-11-13 21:50

- 变了的字段：fingerprint
- 理由：channel_sink_evidence 新增 arg_tainted（零跳污点）；channel_tainted 计算顺序提前；md 加「实参」列变 10 列

## 2026-11-13 22:06

- 变了的字段：fingerprint
- 理由：channel_path_taint 新增（L2）；assignments 不再把 event 参数算脏、await 返回值不继承参数；channel_tainted 结果变少

## 2026-11-13 22:39

- 变了的字段：fingerprint
- 理由：0.120.0 assignments 单参数不再被 event 规则剔空（L3 依赖它）；channel_tainted 结果可能变

## 2026-11-13 23:09

- 变了的字段：fingerprint
- 理由：0.121.0 报告文档更新与版本号；报告字段不变

## 2026-11-13 23:34

- 变了的字段：fingerprint
- 理由：0.122.0 CHANGELOG 与版本号；报告字段不变（靶场没有 webPreferences）

## 2026-11-14 00:43

- 变了的字段：fingerprint
- 理由：参数级污点：每个脏实参都记（renameSync 的 i 和 c 都标）；join 只按根传播

## 2026-11-14 01:00

- 变了的字段：fingerprint, schema
- 理由：新增 facts 字段 channel_state_writes（外部值写进状态字段的写入点与读点），schema 从 asar/24 升到 asar/25，version 同步到 0.124.0。下游若按 asar/24 解包需先校验 schema 再取字段，未登记的消费方会直接看到新顶层键。

## 2026-11-14 01:12

- 变了的字段：fingerprint, schema
- 理由：channel_path_taint 的每条记录多了第 4 项 escape verdict（escapes/anchored/root_unknown，判断 join 或 resolve 能不能真跳出根目录），三元组变四元组，schema 从 asar/25 升到 asar/26。下游若按 asar/25 解这三项会只拿到前两个元素，需先校验 schema 再取 verdict。

## 2026-11-14 01:18

- 变了的字段：fingerprint, schema
- 理由：channel_state_writes 的每条读点多了 kind（read/delete）和 before（是否在写入点之前）两个字段，旧的读点只有 at 和 snippet，schema 从 asar/26 升到 asar/27。下游按 asar/26 取读点时会把 delete 也当成读，需先校验 schema 再按 kind 过滤。

## 2026-11-14 01:37

- 变了的字段：fingerprint, schema
- 理由：channel_state_writes 的每条读点多了 call 字段（落在哪个调用的实参里，不在调用里为 null），schema 从 asar/27 升到 asar/28。下游若按 asar/27 取读点拿不到调用名，需先校验 schema。

## 2026-11-14 01:56

- 变了的字段：fingerprint, schema
- 理由：channel_tainted 的每条从 3 元组变 4 元组，多了 arg shape（direct/wrapped/跨函数），用来区分实参是原样交出去还是先被一层表达式处理过，schema 从 asar/28 升到 asar/29。下游按 asar/28 解包只拿到前三项，需先校验 schema 再取形态。

## 2026-11-14 02:02

- 变了的字段：fingerprint, schema
- 理由：channel_state_writes 的每条多了 via 字段（写入发生在哪个被调函数里，直接写为 null），用来标出写和读被拆到两个函数的形状，schema 从 asar/29 升到 asar/30。下游按 asar/29 取不到 via，需先校验 schema。

## 2026-11-14 02:05

- 变了的字段：fingerprint
- 理由：只升版本号到 0.130.0，报告字段没有任何变化；golden 快照里的 version 字段跟着变，下游按版本号做断言的适配一次即可。

## 2026-11-14 02:12

- 变了的字段：fingerprint, schema
- 理由：channel_path_taint 的 escape verdict 多了 root_param 和 root_local 两种取值，用来区分「根是形参」「根是局部变量」和「根在作用域外」，旧的 root_unknown 含义变窄，schema 从 asar/30 升到 asar/31。下游若按字符串全等匹配 root_unknown，需要先校验 schema 再补两种新取值。

## 2026-11-14 02:19

- 变了的字段：fingerprint, schema
- 理由：path_taint 的 verdict 现在会顺着块作用域解根，root_unknown 可能变成 anchored，判定分布在同一个 schema 号下变了，schema 从 asar/31 升到 asar/32。下游若缓存了旧的 verdict 结果需要重跑，字符串取值本身没增删。

## 2026-11-14 02:25

- 变了的字段：fingerprint, schema
- 理由：新增 facts 顶层键 module_graph（每个打包文件的模块数、依赖边、写法分布），schema 从 asar/32 升到 asar/33。下游按 asar/32 解包看不到这个键，需要先校验 schema 再读；其余字段没有变化。

## 2026-11-14 02:46

- 变了的字段：fingerprint
- 理由：只升版本号到 0.134.0，报告字段没有任何变化；golden 快照里的 version 字段跟着变，下游如果拿版本号做断言需要适配一次。

## 2026-11-14 08:59

- 变了的字段：fingerprint, schema
- 理由：module_graph 的每个文件多了 export_entries、cross_members、cross_resolved 三个字段，用来报「导出表有几项、跨模块取成员几处、其中解出几处」，schema 从 asar/33 升到 asar/34。下游按 asar/33 读不到这三格，需要先校验 schema。

## 2026-11-14 09:20

- 变了的字段：fingerprint
- 理由：只升版本号到 0.136.0，报告字段没有变化；解构别名让部分包的通道数变多，但那是输入决定的，schema 契约本身没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 09:45

- 变了的字段：fingerprint
- 理由：只升版本号到 0.137.0，报告字段没有变化；解构别名让字面扫描层多认出注册点，通道数随输入变，但 schema 契约本身没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 10:30

- 变了的字段：fingerprint
- 理由：只升版本号到 0.137.1，报告字段没有变化；这次修的是常量正则的回溯问题，输出不变，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 10:37

- 变了的字段：fingerprint
- 理由：只升版本号到 0.138.0，报告字段没有变化；这次让 this.method 形态的 handler 能取到方法名，通道的 target 字段从 null 变成名字，schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 11:07

- 变了的字段：fingerprint
- 理由：只升版本号到 0.138.1，报告字段没有变化；这次只改 README 和已知边界，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 11:15

- 变了的字段：fingerprint, schema
- 理由：module_graph 的每个文件多了一个 esm_entries 字段，用来报 ESM 具名导出的条数，跟 CommonJS 的 export_entries 分开算，schema 从 asar/34 升到 asar/35。下游按 asar/34 读不到这一列，需要先校验 schema。

## 2026-11-14 11:23

- 变了的字段：fingerprint
- 理由：只升版本号到 0.140.0，报告字段没有变化；这次加的是跨文件一跳和 span 语义修正，输出随输入变但 schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 11:27

- 变了的字段：fingerprint
- 理由：只升版本号到 0.141.0，报告字段没有变化；这次补的是整体重赋值和导出类两种形态，输出随输入变但 schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 11:51

- 变了的字段：fingerprint
- 理由：只升版本号到 0.142.0，报告字段没有变化；这次把常量下标和字面量数组循环也枚举成具体导出名，输出随输入变但 schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 12:03

- 变了的字段：fingerprint
- 理由：只升版本号到 0.143.0，报告字段没有变化；这次补了字面量拼接常量折叠和 ESM 导入的跨文件跟随，输出随输入变但 schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 12:09

- 变了的字段：fingerprint
- 理由：只升版本号到 0.144.0，报告字段没有变化；这次补了跨文件常量解析和两跳纯转发，输出随输入变但 schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 13:02

- 变了的字段：fingerprint
- 理由：只升版本号到 0.145.0，报告字段没有变化；这次修的是 benchmark 脚本合并两路证据、以及未标注包的显示，产品输出没变，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 13:19

- 变了的字段：fingerprint, schema
- 理由：新增 facts 顶层键 taint_truncated（因深度上限被砍断的跨函数链条数，没有下一跳的不算），报告里多一行说明，schema 从 asar/35 升到 asar/36。下游按 asar/35 读不到这个键，需要先校验 schema。

## 2026-11-14 13:25

- 变了的字段：fingerprint
- 理由：只升版本号到 0.147.0，报告字段没有变化；这次让同文件常量驱动的动态注册点也能解析出通道名，并新增对抗性视角文档，schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 13:33

- 变了的字段：fingerprint
- 理由：只升版本号到 0.148.0，报告字段没有变化；这次补了 fromCharCode、模板常量插值和对象键枚举三种通道名写法，schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 13:58

- 变了的字段：fingerprint, schema
- 理由：scan_asar 的 facts 多了 taint_truncated 键（明确写 None 表示这一层没测，不是零），schema 从 asar/36 升到 asar/37；同时修了截断计数用错筛子、以及没有脏实参也算截断两个问题。下游按 asar/36 读不到这个键，需要先校验 schema。

## 2026-11-14 15:23

- 变了的字段：fingerprint
- 理由：只升版本号到 0.150.0，报告字段没有变化；这次加了函数摘要 API 和函数体分析缓存，主链路结论不变、耗时不变，schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 15:30

- 变了的字段：fingerprint
- 理由：只升版本号到 0.151.0，报告字段没有变化；这次加了局部子图摘要与子图可达查询（opt-in，主链路未切换），schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 15:41

- 变了的字段：fingerprint
- 理由：只升版本号到 0.152.0，报告字段没有变化；这次补了同名多候选边的最近候选选取与歧义计数，主链路未切换，schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 15:52

- 变了的字段：fingerprint
- 理由：只升版本号到 0.153.0，报告字段没有变化；这次修掉 function_defs 把控制关键字当函数名的问题，并给同名候选加了形参个数粗筛，主链路未切换，schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 16:19

- 变了的字段：fingerprint
- 理由：只升版本号到 0.154.0，报告字段没有变化；这次把关键字排除做成自检断言、并把 ADR 阈值按包结构分层，schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 16:45

- 变了的字段：fingerprint
- 理由：只升版本号到 0.155.0，报告字段没有变化；这次把三层各自的关键字清单合成 jskw.JS_RESERVED 一份并加断言，schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 16:53

- 变了的字段：fingerprint
- 理由：只升版本号到 0.156.0，报告字段没有变化；这次给子图摘要的每个 sink 加了 via 路径（经过哪些函数才摸到），主链路未切换，schema 契约没动，golden 里只有 version 和 fingerprint 变。

## 2026-11-14 17:23

- 变了的字段：fingerprint
- 理由：只升版本号到 0.157.0，报告字段没有变化；这次加了子图/全量摘要的镜像测试、修掉全量摘要缺函数名的问题、并立起 sanitizer 语料骨架，schema 契约没动，golden 里只有 version 和 fingerprint 变。
