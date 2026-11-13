# ipcsurface

[![version](docs/badges/version.svg)](https://github.com/irrational51444/ipcsurface/releases)
[![tests](docs/badges/tests.svg)](tests/test_ipcsurface.py)
[![python](docs/badges/python.svg)](pyproject.toml)
[![license](docs/badges/license.svg)](LICENSE)

**把一个 Electron 应用的能力面压成一页纸。** 零依赖，只装 Python。当前 **0.107.0**。

`ipcsurface` 读一个 `.asar` 包（或 REA 的 Evidence JSON、一个 dll/exe），输出报告：有几条 IPC 通道、哪些名字是写死的、哪些是还原出来的、哪些只是长得像——以及**这份报告能信到什么程度、你凭什么自己核对**。

[English README](README.en.md) · [变更记录](CHANGELOG.md) · [示例靶场](examples/README.md) · [已知会错的地方](docs/known-wrong.md)

---

## 真跑一次

本机一个真实的 Electron 应用，441 MB、22,102 个文件，5.0 秒：

![真实应用扫描输出](docs/img/case-real-scan.png)

一条命令出报告，再拿人工标注对账（召回 / 精确 / 总覆盖率）：

![示例靶场与对账](docs/img/case-fixture-run.png)

三道闸，本地和 CI 跑同一套：

![三道闸](docs/img/case-gates.png)

---

## 两个例子，都是真跑出来的

### 一、靶场：三条通道，一条安全、一条写文件、一条执行命令

样品不用我发，一条命令就能造出来：

```bash
python scripts/make_demo_asar.py build/demo.asar
python ipcsurface.py build/demo.asar
```

![靶场跑一遍](docs/img/example-demo.png)

这份报告说明三件事：`demo:ping` 什么都没碰到；`demo:save-note` 能写文件、
`demo:run` 能执行命令；而且这两条**外部输入直接到了危险参数上**——
这是「该动手看」的那批，不是提醒。

### 二、真机：Obsidian 26.8 MB 的 `obsidian.asar`

```bash
python ipcsurface.py "/path/to/Obsidian/resources/obsidian.asar"
```

![Obsidian 跑一遍](docs/img/example-obsidian.png)

同一个包里，粗扫说 19 条通道能碰到危险 API，语法树说 22 条——
差的那几条是成员调用、别名这类写法，名字级匹配认不出来。
其中 11 条我一条条读过源码确认（`print-to-pdf` 真 `writeFile`、
`vault-move` 真 `renameSync`、`sandbox` 真的会 `rmSync`…），
剩下的是「这条链路我看见了，但没人工核」。

## 0.85.0 这一版新加的，都是真跑出来的

### 能力面不止 IPC 通道

`attack_surface` 盯六个面：`shell-open`、`exec-js`、`permission-handler`、
`custom-protocol`、`deep-link`、`webview`。每条带参数强弱档——参数是写死的值，
还是可能从外部进来的活值，分两档报。

### 双引擎精查（opt-in）

`--precise` 用 tree-sitter 重走一遍：跨文件 `require`、类方法跟随、循环枚举
（`for (const x of [...]) ipcMain.on(x)` 能展开）。默认零依赖不变，装 extra 才启用：

```bash
pip install 'ipcsurface[precise]'
python ipcsurface.py app.asar --precise -o report.md
```

### 运行时探针对齐（静态猜不到的，让它自己说）

`probe/run.js` 在真 Electron 里起靶场，读运行时注册的通道，跟静态对账。本机
虚拟机（Ubuntu 26.10 + xvfb + Electron）跑通：运行时 7 条、静态认得 5 条、总对齐
71%，**应用自己注册的 5 条 5/5 全对齐**，差的 2 条是 Electron/Node 内置。这条已经
落进 CI（对齐率低于门禁就红）。

### 每条危险 API 的来路可信度

`channel_sink_tiers` 给每条报出的危险 API 标档：直连 / 双口径证实 / 同文件链 /
同名多义借来 / 仅语法树借来。`channel_sink_evidence` 再给每一条配一份**凭据**：
档位、几跳、经过哪些函数名、位置（`文件:行@字符偏移`，压缩包的整个文件常常只有
几行，只给行号等于没给）。

拿 6 个真包人工对账（`scripts/calibration.py`）：

| 来路档 | 对 | 误报 | 精确率 |
| --- | --- | --- | --- |
| 直连 / 双口径 / 同文件链 | 18 | 0 | 100% |
| 同名多义借来 | 8 | 7 | 53% |
| 仅语法树借来 | 1 | 3 | 25% |

**这 18 条可以直接引用，下面两档不用信也不用核**——报告里它们的「经过」列会写
「同名多义」，md 里还有专门一节把借来的 API 按位置列出来。精确率 24% 是实话，
但复核成本不一样了：原来 114 条逐条看，现在硬档直接读，软档扫一眼跳过。

路径越可信，精确率越高，**单调成立**——这条由校准脚本断言守着，不是嘴说。

### 基准对账（6 个真包）

`scripts/benchmark.py` 通道级精确率 100%、召回率 96%；API 级精确率 24%——这个
24% 是实话：共用函数被保守跟进去，报出来的远多于该通道真有的。语料库 6 个真包
（Obsidian / DeepSeek Harness / 抖音 / bilibili / vivo / ACLOS），边界样本也入库，
见 `docs/benchmark.md`。

## 为什么不是「扫出通道数」就完事

同一份报告里的话，强度不一样。上面那份真实报告：

| 这一层 | 数量 | 能证明什么 | 不能证明什么 |
| --- | --- | --- | --- |
| 写死的名字 | 11 条 | 源码里逐字写着，`file:line` 能回到原文复核 | 只覆盖写死的写法 |
| 靠还原才认出的 | 84 条 | 名字从字符串池/常量表里查出来的，出处还在源码里 | 查得出不等于它真是通道 |
| 名字是算出来的 | 0 条 | 知道这里在调用，名字不是写死的 | 名字是什么，算不出来 |
| 捞出来的候选 | 221 个（51 个它自己写的） | 这些字符串长得像通道名 | 长得像不等于就是 |
| 没看见的 | 未知 | 无 | 这条路看不见，不代表它不在 |

**这几层不可相加。** 真实报告共 41 条通道、221 个候选；同一个名字可能既被还原、又被运行时看到，两边都会算它。报告是地图，不是判决书。

**「221 个候选」这个数到底有多准？** 有数字的部分就报数字，没有的就写没有：

先分档，再谈准不准。分档只用能机械判的事实（是不是通道名、在不在含 IPC 的文件里、同前缀几个），不做语义猜测：

| 档位 | 真实应用 | 意思 |
| --- | --- | --- |
| 就是通道 | 41 | 和静态看见的通道名对上了，不用再猜 |
| 在含 IPC 的文件里 | 10 | 名字躺在注册表或调用旁边，最值得先看 |
| 同前缀成簇 | 89 | 像一张名字表，`tool` / `js` 这类前缀最多 |
| 零星 | 81 | 只在别处出现，最可能是噪音 |

**要人工看的从 221 个降到 51 个**（前两档），其余 170 个默认只报数量、加 `--all` 才展开。然后才是准确率：

- **靶场**（`python scripts/harvest_precision.py`）：17 个候选，17 个确实是通道名，准确率 **1.00**——但靶场是我自己写的、样本很小，说明不了真实应用。
- **真实应用**：221 个候选里，41 个同时也是静态看见的通道名（那不是误报，是同一件事的两条路）；剩下 **180 个孤证**。这 180 个里，只有 12 个出现在提到 IPC 的文件里、**0 个**紧挨调用（它们长在名字表里，不长在调用旁边），168 个只在别的文件里出现；96 个成簇（同前缀 ≥3，最大的是 `tool=16`、`js=15`），84 个零星。
- **准确率：未知。** 这 180 个没有人工核对过，编一个数比留空更坏。

还有一层这张表里没有，因为**这个包 0 条**：穷举出来的名字（`enumerated`）。取值集合是源码里的字面量数组、拼法是字面量加参数时，`for (const op of OPS) ipcMain.handle(makeChannel(op))` 这种能算成三个具体名字。靶场 `dyn` 里就是三条，真实应用很少这么写。

这一层分两档，**强弱看证明，不看心情**：三条检查（循环里没改过循环变量、数组没被 push/splice 改过、拼装函数只有一个表达式）全过是 **0.9**，和「靠还原」同档；有一条没过降到 **0.6**，名字照给但别当准的用。哪条没过写在 `enum_proof.failed` 里。

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
python ipcsurface.py app.asar -o report.md              # markdown
python ipcsurface.py app.asar --format json -o r.json   # 机器读的
python ipcsurface.py app.asar --baseline last.json      # 只看新冒出来的
python ipcsurface.py app.asar --fail-on high            # 有高危项退 2，挂 CI
```

自带靶场可以直接试（要先造包）：

```bash
cd examples && bash build.sh
python ipcsurface.py build/static-asar.asar -o report.md
```

---

## 这份报告的三条规矩

**一、未知写 `null`，不写 `0`。** 没看见不等于没有；`0` 会被读成「确认没有」。

**二、证据只记来源，不下结论。** 每条通道都带 `evidence`：名字从哪来、强度多少、**哪几种观察能推翻它**。强度排的是复核成本，不是概率。

**三、消费方必须先校验 `schema`。** 现在是 `ipcsurface/asar/24`；对不上就停下，别按字段在不在猜。

---

## 可信度靠什么撑起来

不是靠形容词，靠六件能被别人自己核对的事：

- **报告自指纹 `content_digest`**：报告正文（去掉时间戳和它自己）的 sha256。谁拿到都能重算——对得上，说明没被改过、也不是别的版本生成的。
- **包级 Merkle 根 `archive_merkle`**：包内每个文件的 `路径:sha256` 排序聚合，确认「我们说的是同一份包」。
- **完整性凭证都带 `claim` 字段**：`proves` 是「同一份东西、生成后没被改过」，`does_not_prove` 明写不是 `safety`、不是 `absence_of_backdoor`，`security_rating` 恒为 `false`。以前「这不是安全评级」只写在说明里，现在它是报告里的一格，读的人绕不过去。
- **输入指纹 `fingerprint`**：输入 sha256 + 版本 + schema + 参数 + 通道名，一起算。同输入重跑必须同值；输入读不到就是 `null`，不编。
- **每条结论配「推翻它的判据」**：`evidence[*].refutes_if` 写的是「什么观察能驳倒这条」，不是「什么能支持它」。
- **每层给样本，JSON 给全量**：md 每层抽两条 `名字 @ file:line`（按名字 sha1 选，谁的机器上都一样）；JSON 里 `sites` 给全部位置，`evidence[*].where_all` 给每个名字的所有位置。
- **人工标注对账**：`tests/golden/ground_truth.json` 是逐份源码数出来的通道清单，`scripts/ground_truth_check.py` 算召回 / 精确 / 总覆盖率。**当前平均总覆盖率 1.00**——四个靶场全对上了（`dyn` 那三条以前是「算不出来」，这一版才穷举出来）。**这个 1.00 只说明这四个靶场**：加起来 23 条通道、写法全是我自己写的，不代表真实应用；`known_unreachable` 这一栏现在是空的，空了才敢说满，但它跟着源码变。

交叉强度的四档（`strong` / `medium` / `weak-same-line` / `weak-near-line`）不是摆设：探针在 probe JSON 里给 `sites`（名字 → `file:line`），工具就按两侧位置算档。**探针只报名字、不报位置时才是 `unknown`**——那是没算，不是没对上。这四个档都用真实 CLI 跑出来过。

---

## 退出码

| 码 | 意思 | 该做什么 |
| --- | --- | --- |
| 0 | 成功，没有触发门禁 | 持久性看 stderr 的 `kind:` 行 |
| 1 | 输入有问题（文件不存在、不是 asar、参数不对） | 照提示修输入 |
| 2 | `--fail-on` 被触发 | 看报告里的可疑项 |
| 3 | 工具自己崩了 | 报 issue |
| 4 | 已写入但未持久化（目录 fsync 失败） | **文件已是新版，不要回滚、不要重跑** |

发布脚本的退出码是另一套：`0` 成功、`1` 守卫红或 release 已存在、`2` 守卫查不到、`3` 脚本自己出错。**非零不等于失败**，这几种要分开。

---

## 写入可靠性 / 崩溃残留

报告「要么完整、要么不动」：先写同目录临时文件、`fsync`、核字节数，再 `os.replace` 原子换上去。任何时刻从约定路径读到的都是完整报告。

- **目录 fsync 失败**不等于写失败，内容已替换，只是崩溃后可能回退。`durable` 是三态：`yes` / `no` / `unknown`；`unknown` 只在「这套系统根本没有刷目录的办法」时出现，退出码仍是 0。
- **替换被占用**报 `replace_failed`，这次的正文留在 `.failed` 里当现场，原报告不动。
- **崩在中间**会留下 `.bak` / `.failed`，用 `--recover` 看：

```bash
python ipcsurface.py --recover out.md
```

只给事实、不动文件：副本存在只说明「上次可能崩在替换与清理之间」；target 缺失时整张对比表退化成副本清单（大小、年龄、年龄的时间来源都保留），不留半张只有一侧的表。前跳识别的「一年」是**启发式**，正常旧文件也会落进来，要改只能改源码。

## 错误词表（机器可读）

输入侧：`file_missing`、`empty_input`、`encoding_invalid`、`json_truncated`、`json_malformed`、`shape_invalid`、`depth_exceeded`。

输出侧：`disk_full`、`permission_denied`、`short_write`、`replace_failed`、`symlink_target`、`write_failed`、`invalid_json_output`。

---

## 质量怎么保证的

- **432 个用例**，只跑标准库：`python -m unittest discover -s tests`
- **性能门禁**：python scripts/perf_check.py，固定种子造包测吞吐，低于下限 CI 红（README 的性能数字也从这个脚本复现）
- **分支覆盖率 67%**，只许涨不许跌：`python scripts/coverage_check.py`（CI 也守这条，掉下去就红）
- **冒烟 15 项**：真跑一遍 CLI 的所有入口，跳过也出声，汇总行由脚本自己算
- **输入解析 fuzz**：`python scripts/fuzz_smoke.py` 字节级变异 asar 头 / PE 导入表；CI 里另跑 30 秒 atheris 真 fuzz
- **基准测试**：`python scripts/benchmark.py`，通道级 / API 级的精确率与召回率（数字写进 `docs/benchmark.md`）
- **可信度校准**：`python scripts/calibration.py`，按证据强度档和 sink 来路档分层算精确率，照出「哪个档名不副实」
- **运行时对齐**：`python scripts/probe_align.py probe.json app.asar`，静态认得几条运行时通道；应用通道要全对齐
- **端到端**：`python scripts/e2e_check.py`，走装好的命令行，验 schema、口径、退出码、确定性，再跑一遍人工标注对账
- **自查**：版本 / 打包元数据 / schema / 规则注册表 / 文档与实现一致 / 工作区干净 / 已知会错清单的下限；--fast 跳过真包和冒烟，116 秒降到 20 秒（CI 用，发版门禁仍跑全量）
- 三道闸一条命令：`bash scripts/verify.sh`，CI 也跑它

CI 六个任务，缺一不可：

- `check`（Linux）：装包、造示例包、三道闸、覆盖率门禁、性能门禁
- `windows`：同一套三道闸，外加 Windows 专属断言（目录刷盘走 `FlushFileBuffers` 且 `durable` 必须是 `yes`、替换被占用报 `replace_failed`、263 字符长路径写得出来）
- `fuzz`：30 秒 atheris 短 fuzz（三个解析入口）
- `probe`：xvfb + Electron 起靶场，跑运行时探针，对齐率低于门禁红
- `signal`：干净包退 0、有问题的包退 2、SARIF 能上传
- `e2e`：装成包 → 对可复现靶场跑 → 校准 schema 与口径 → 人工标注对账

发布也不靠记性：`check_release_tag.py` 查标签指向的提交是否 CI 全绿（`0` 绿 / `1` 红 / `2` 查不到，**还没跑完也算查不到**），`make_release.py` 先过守卫再发（`3` 是脚本自己出错）。两张脚本自己都有用例。

---

## 已知会错的地方

拼出来的名字看不见、长得像的字符串会误报、混淆器的痕迹只是线索——按「看不见的 / 会误报的 / 别当结论用的场合」写在 [docs/known-wrong.md](docs/known-wrong.md)。

清单有机械下限：三列固定、症状条数不少于八条、顶部版本锁与当前版本一致，自检核对。**内容是判断，自检保证不了它够具体**——这条边界写在 README 里，不装作能自动判断质量。

## 代码结构（主模块开始拆了）

ipcsurface.py 五千多行，什么都装在里面，改一处要读全部。现在按层往外搬，搬一个验一个：

| 文件 | 管什么 |
| --- | --- |
| jsasar.py | asar 读取：头解析、文件表、按需切片（第一刀，108 行） |
| jslabels.py | 报告要用的说法：时间戳、危险 API 归类、候选分档（第二刀） |
| jsreport.py | 报告层：Markdown 渲染、基线比对、可信度分层、指纹（第三刀，818 行） |
| jsparse.py | 词法：认不出的字符、未闭合的字符串都不再让整份分析作废 |
| jssem.py | 污点与可达性：赋值、回调、循环变量、catch 变量的传播 |
| jsast.py | 语法树：成员调用、方括号、别名、回调连边 |
| native_imports.py | PE 导入表：原生模块能力面（加壳读不出就写「读不到」） |
| precise_engine.py | tree-sitter 精查层（opt-in）：跨文件 require、类方法跟随、循环枚举 |
| ipcsurface.py | 扫描、证据、报告、命令行（还在往外搬） |

搬完这一层，295 条用例、四道闸、真包数字全都没变——这是能搬的前提。

## 解析器的选型与边界

手写解析器的取舍、实测覆盖率和「什么情况下会翻案」写在
[docs/parser-decision.md](docs/parser-decision.md)；它认哪些语法、不认哪些，一条条列在
[docs/known-wrong.md](docs/known-wrong.md) 的「解析器语法边界」一节。覆盖率能用
python scripts/ast_coverage.py 在任意包上重测（输出未知节点率、吞吐、结构量）。

## 已知边界

- 字符串级粗扫，不建语法树。拼出来的名字只有一种能算：取值集合是字面量数组、拼法是字面量加参数，那就穷举（`enumerated`：证明齐 0.9，缺证明 0.6）；取值来自配置、函数返回值或循环累加的一律退回「算不出来」。要准的走 REA Evidence。
- 沙箱、原生模块、运行时才装配的通道，静态看不到。
- Windows 上目录刷盘用 `ctypes` 调 `FlushFileBuffers`（句柄要带写权限，读权限会被拒）。只读卷和网络盘没实测过——那种情况下报 `durable=no`，不是 `unknown`。
- `adv-asar.asar` 是对抗样本，没有生成脚本，只在本地有；其余靶场都能由 `examples/build.sh` 重造。
- **「0 条」的读法**：channel_sinks 是粗扫口径（名字级匹配），channel_sinks_ast 是语法树口径（成员调用、方括号、别名、回调都能连）。两条都为 0 时只能读成「这个包里没连到」，不是「确认没有」；跨文件的调用树还跟不过去，这条缺口写在 docs/known-wrong.md。
- 规模与性能的断言可以**由外部复现**：`python scripts/make_scale_asar.py out.asar --files 22102 --mb 441` 按固定种子造出同量级的包（22,103 个文件 / 448.7 MB），再跑 `python ipcsurface.py out.asar --format json`。本机实测 **70.5 秒**、44,204 条通道结论。作者本机那个 441 MB 的应用是另一份样本，两个数字不要混着引用。

---

## 维护者自查（写给改它的人）

- 用例数、冒烟项数只写在上面「质量怎么保证的」那一节，别处引用不重写——两处会漂。
- 全称断言的空集合防护按语义判：内建集合操作（`len`、`sum`、`count`、`index`、`sorted`、`set`、`all`/`any`、推导式、空容器）算集合自身属性；用户自定义函数、依赖外部状态的调用才算「函数返回值」，一律保守归真空。
- 发布前跑一次 `python scripts/check_release_tag.py v<版本>`。它的 `2` 是「查不到」，不是「CI 红」。
- `check_release_tag.py` 第一次跑就发现 `v0.62.0` 发布时 CI 是红的；该版本不追溯修改，仅记录（CHANGELOG 0.65.5）。
- 注释豁免要贴着断言写（中间不许夹语句），比率当前是 **5 / 6**（真空断言口径）——这个数涨了就是信号。

## 设计原则（写给以后改它的人）

1. 不把不知道报成知道。
2. 每个失败说清坏在哪、下一步做什么。
3. 纪律变成断言，不变成 README 里的一句话。
4. 测试要证明「该拦的拦住了」和「该放的放过了」，两条都要。

---

## 许可

MIT，见 [LICENSE](LICENSE)。
