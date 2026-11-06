# ipcsurface

**把一个 Electron 应用的能力面，压成一页纸。**

[![ci](https://github.com/irrational51444/ipcsurface/actions/workflows/ci.yml/badge.svg)](https://github.com/irrational51444/ipcsurface/actions/workflows/ci.yml)
[![version](https://raw.githubusercontent.com/irrational51444/ipcsurface/main/docs/badges/version.svg)](CHANGELOG.md)
[![tests](https://raw.githubusercontent.com/irrational51444/ipcsurface/main/docs/badges/tests.svg)](tests/test_ipcsurface.py)
[![python](https://raw.githubusercontent.com/irrational51444/ipcsurface/main/docs/badges/python.svg)](pyproject.toml)
[![dependencies](https://raw.githubusercontent.com/irrational51444/ipcsurface/main/docs/badges/deps.svg)](ipcsurface.py)
[![license](https://raw.githubusercontent.com/irrational51444/ipcsurface/main/docs/badges/license.svg)](LICENSE)

> 徽章都是仓库里自己的 SVG，不连 shields.io——那层代理在国内经常是空的，图会挂成一条竖线。

---

## 它解决的问题

Electron 应用的能力，一半在主进程里。渲染进程碰不到文件、碰不到磁盘、碰不到网络底层，全都要过 `ipcMain` 那几扇门。

门是 preload 拿 `contextBridge` 开出来的。开的时候没人记账，半年后就没人数得清有多少扇、哪扇通向哪里、哪扇是谁加的。

这个工具把这些门摆到一页纸上，并且**先说这份纸能信几成**。

---

## 三种输入

| 输入 | 需要什么 | 准到什么程度 | 适合什么时候 |
| --- | --- | --- | --- |
| `app.asar` | 只要 Python | 字符串级，带几道还原 | 刚拿到包，想知道值不值得认真查 |
| REA Evidence | Python + REA | 语法级：建图、跟作用域、带行号 | 真要出结论 |
| `x.dll` / `x.exe` | 只要 Python | 导入表：只说引了哪些外头函数 | 往下走一层，看它靠什么干活 |

三种都出同一套报告，第一节永远是「这份报告能信多少」。

---

## 名字藏起来了怎么办

真实应用发出去是压过的，`ipcMain.handle('vault:unlock')` 会变成 `a.b(c[3], d)`。这是字符串级扫描的死穴。

但真名往往还在包里，只是换了写法。下面几道还原全在粗扫里自动跑，一道都**不执行目标里的代码**：

| 手法 | 长什么样 | 怎么还原 |
| --- | --- | --- |
| 字符串池 | `var _0x=['vault:unlock',…]` 配 `_0x[0]` | 找到全是字符串的数组，下标换回字面量 |
| 死拼接 | `'ledger:' + 'shadow'` | 两头都是字面量，折成一段 |
| 模板串 | `` `ledger:${'tpl'}` `` | 插值是写死的，摊平；带换行的不摊，免得行号偏 |
| 常量 | `const PREFIX='ledger:'` 配 `PREFIX + name` | 前缀代回去 |
| **常量对象** | `const CH = { boot: 'dsh-desktop:boot' }` 配 `ipcMain.handle(CH.boot)` | 收全包的常量对象建表，`对象.字段` 换成登记的值 |
| 跨文件 | 名字写在 `channels.js`，`main.js` 里 `handle(CHANNEL)` | 先把全包的常量和常量对象收成两张表，第二遍扫时查表 |
| 方括号取成员 | `ipcMain['handle']('vault:unlock')` | 认成员访问的两种写法 |
| unicode 转义 | `'vault:\u0075nlock'` | 字面量里预解码；控制字符不还原，免得把行数撑开 |
| 自解码函数 | `_d('\x71\x66…')`，函数体里逐字符异或 | 认函数体的形状，用纯 Python 算，套几层剥几层 |
| 打捞兜底 | 调用点认不出了，名字还在字符串里 | 抽出所有 `前缀:名字`，去噪，按位置列出来 |

**真包上的结果**：一个 441 MB、22,102 个文件的真实应用，粗扫认出 **41 条通道**，其中 41 条全是靠常量对象查出来的，一条都没逐字写在调用点上。兜底再捞 **221 个候选**，其中 **51 个是这应用自己写的**，剩下的是第三方库和测试的噪音。

从零翻起、拿 221 行名单翻、拿 51 行名单翻，是三件不同的事。后面两档差的就是这道分家。

---

## 安装

Python 3.9+，只用标准库。

```bash
pip install .
```

不装也行，`python ipcsurface.py --help` 直接跑。只有想用语法级分析才需要 REA：`npm install -g rea-agents`。

---

## 快速开始

**糙的**，一个包换一页纸：

```bash
ipcsurface app.asar surface.md
# wrote surface.md — 41 条通道，0 条可疑，0 处名字是算的
```

**准的**，两步：

```bash
rea analyze-javascript-application app.asar --detail summary --evidence_output evidence
ipcsurface evidence surface.md
```

**只报新冒出来的**：

```bash
ipcsurface app.asar --write-baseline base.json -o surface.md   # 第一次
ipcsurface app.asar --baseline base.json -o surface.md --fail-on high
```

审计工具不解决噪音就没人用。一上来二十条高危，看三遍就麻木了。基线让「这次改动引入了什么」成为唯一的问题。

**比两个版本**，升级后多了哪扇门：

```bash
ipcsurface old.asar --diff new.asar -o change.md
```

**往下走一层**，看一个 dll 靠什么干活：

```bash
ipcsurface some.dll -o imports.md
```

常用参数：

| 参数 | 作用 |
| --- | --- |
| `-o, --out` | 写到文件；不给就打到标准输出 |
| `--format json` | 三种输入都支持，字段见下面「机器可读」 |
| `--fail-on high` | 出现该级别及以上问题时退出码 2，可以挂 CI |
| `--diff OTHER` | 把输入当旧版，和另一份比 |
| `--baseline FILE` | 只报基线里没有的发现 |
| `--write-baseline FILE` | 把这次的发现存成基线 |
| `--no-eval` | 关掉自解码还原。默认开着 |
| `--deep-restore` | 还原多转几趟。默认一趟，实测多转没多认出东西 |
| `--runtime PROBE` | 并入运行时探针的结果 |
| `--poke POKE` | 并入真敲一遍的结果 |
| `--all` | 不截断 |

---

## 输出长什么样

![真实输出：对一个 5 条通道的应用跑出来的报告](https://raw.githubusercontent.com/irrational51444/ipcsurface/main/docs/preview.png)

真跑出来的，`examples/build.sh` 一遍就能复现。报告结构固定：先说能信多少，再列证据，最后说没看清什么。

---

## 报告怎么读

这是这个工具最要紧的一节。**同一条报告里的话，强度不是一样的。**

报告开头有一张表，每行写三件事：有多少、能证明什么、不能证明什么 / 下一步怎么办。真包上的样子：

| 这一层 | 有多少 | 能证明什么 | 不能证明什么 |
| --- | --- | --- | --- |
| 两条路都对上的 | 31 条 | 静态和运行时各看见一次，互不依赖 | 对上的是名字，不是行为 |
| 写死的名字 | 11 条 | 源码里逐字写着，能回原文复核 | 只覆盖写死的写法 |
| 靠还原才认出的 | 84 条 | 从字符串池、常量、常量对象查出来，出处还在源码里 | 查得出不等于它就是通道 |
| 名字是算出来的 | 0 处 | 知道这里有调用 | 名字是什么，算不出来 |
| 打捞出来的候选 | 221 个（51 个是自己写的） | 长得像通道名 | 像不等于就是 |
| 没看见的 | 未知 | —— | 我这条路看不见，不代表它不在 |

三条读法上的规矩，写进了 JSON 的 `usage_constraints`，也写在这儿：

- **六层是标签，不是分类。** 一个名字可能同时落在几层，别把那一列加起来当总数。唯一能当总数的是 `unique_names`。
- **强度是复核成本，不是概率。** 查表查出来的名字和逐字写着的，确定性没差别；差的是复核要看一处还是两处。
- **`strength` 说「最好的那条多硬」，`weakest_sources` 说「最薄的环节多薄」。** 一条 0.9 的记录里可能挂着 0.2 的来源，两个数不能互相替代。

---

## 让程序自己说

静态只能猜。这两步是问。

```bash
cd probe && npm install

# 读登记表：注册了哪些通道、窗口真实的 sandbox 值
node run.js 应用目录 6 > probe.json

# 真敲一遍：每条通道喂 undefined、空对象、十万字符、null
node poke.js 应用目录 6 > poke.json

ipcsurface app.asar --runtime probe.json --poke poke.json -o surface.md
```

读登记表那步，混淆是没用的——代码在磁盘上乱名，跑起来内存里是明文。真包上读到 **27 条 invoke 通道、6 个监听、1 个窗口**，窗口那三项是 `contextIsolation=true`、`nodeIntegration=false`、`sandbox=true`。

敲击那步分三档写，不是两档：

- **照收的**：喂什么都不看还返回结果，最值得看。真包上 0 条。
- **被拦下的**：原话是 `rejected IPC without a sender frame` 这类。真包上 26 条。这一档只证明**有个门**，证明不了门后面对参数做过校验——sender 管的是「谁在调」，不是「传了什么」。
- **门禁未知**：抛了错，但抛的不是拦截类的话。这条错误**不提供门禁信息**，既不能说有门，也不能说没有，要回去看代码。

**在真包上跑起来要过两道关**，都是实测撞出来的：

1. 单实例锁按 userData 目录加，探针默认给一份独立的 `--user-data-dir` 绕开；
2. 应用可能在未打包启动时要一个环境变量指路（比如 `DSH_DESKTOP_PRIMARY_RUNTIME_DIR`），不给就起不来、窗口一个都建不出来。

这套配方只在一个应用上验过，换个包大概率要重摸一遍，别当通用解法。

**注意**：敲击会真的执行目标代码。只对自己的靶子或明确授权的程序用。

---

## 拿一个真包从头走到尾

不是演习。一个 **441 MB、22,102 个文件**的真实 Electron 应用：

| 步骤 | 用时 | 结果 |
| --- | --- | --- |
| 粗扫 | 4.4 秒 | 41 条通道，捞到 221 个候选，峰值内存 411 MB |
| 语法级 · 全量 | **十分钟没跑完** | 放弃，换下面的方式 |
| 语法级 · 挑文件 | 54 秒 | 产出 259 MB 证据 |
| 读证据 | 2.4 秒 | 一页报告 |
| 摊成目录给探针用 | 17 秒 | 22,102 个文件 + 7,727 个包外文件 |
| 探针 + 敲击 | 各十几秒 | 27 条通道、26 条被拦 |

三件事写进了代码里：

**全量语法级分析在大包上跑不动。** 读一遍和读懂一遍是两回事：两万多个文件读进来 0.3 秒，给每个建语法树、连引用、推数据流是另一笔账。正确姿势是先粗扫打捞，挑出可疑文件，再 `--source-path` 精查那一个。

**单文件分析缺上下文，就别硬下结论。** 只喂一个文件时看不到窗口代码，那「一条 sender 校验都没有」就不成立。

**证据大不等于慢。** 259 MB 的 JSON 读一遍 2.4 秒。

---

## 机器可读

`--format json` 给的不是「另一份人话」，是同一套判断的字段化版本。schema 现在是 `ipcsurface/asar/10`。

```json
{
  "schema": "ipcsurface/asar/10",
  "unique_names": 234,
  "channels": ["dsh-desktop:boot", "…"],
  "confidence": [
    {"id": "corroborated", "count": 31, "strength": 0.9, "action": "cite_with_caveat",
     "can_prove": "…", "cannot_prove": "…", "next_step": "…"}
  ],
  "evidence": {
    "dsh-desktop:boot": {
      "sources": ["harvested", "literal-resolved", "runtime"],
      "strength": 0.9,
      "strength_by_source": {"literal-resolved": 0.9, "runtime": 0.8, "harvested": 0.2},
      "weakest_sources": ["harvested"],
      "weakest_strength": 0.2,
      "corroboration": "static_runtime",
      "corroborated": true,
      "actions": ["spot_check_source", "triage", "trust_after_setup"],
      "primary_action": "triage",
      "independent_pairs": ["harvested+runtime", "literal-resolved+runtime"]
    }
  },
  "confidence_semantics": {"…": "规则都在这儿，不写在文档里"},
  "limits": ["…"],
  "baseline": null
}
```

几条定死的：

- **未知写 `null`，不写 0。** 0 会被下游读成「查过，没有」。
- **`primary_action` 只是先做哪件事**，不能替代 `actions`；主动性作取最严格的那个（`cite` < `spot_check_source` < `trust_after_setup` < `read_code` < `triage`）。
- **独立性有一张十组判定表**，不是几个例子：静态来源之间（`literal` / `literal-resolved` / `computed` / `harvested`）共享同一份源码，不算独立；运行时与任一静态来源算独立。每个名字的 `corroboration` 已按表算好。
- **`must_not` 是声明，不是闸门。** 它表示「工具声明了这条禁令、并且它有出处」，不表示「工具能检测你有没有遵守」。遵守责任在消费方。
- **消费方必须先校验 `schema` 号**，不匹配就拒绝解析。换号只保证你能察觉不兼容，察觉与否取决于你有没有看。

---

## 输出契约与 CI 信号

CI 只认三样东西：**退出码、可解析的结构、稳定的规则 id**。三样都定死在这儿。

**退出码**

| 码 | 意思 |
| --- | --- |
| 0 | 没有触发门禁 |
| 1 | 输入有问题：文件不存在、不是 asar、参数不对 |
| 2 | `--fail-on` 被触发 |
| 3 | 工具自己崩了——不是目标的问题 |

代码里是 `EXIT_CODES`，测试直接断言这张表，改口径会红。

**三种输出，各有各的用途**

| `--format` | 给谁 | 说明 |
| --- | --- | --- |
| `md` | 人 | 默认。先说能信多少，再列证据 |
| `json` | 程序 | `schema` 号打头，字段见上一节 |
| `sarif` | CI 平台 | SARIF 2.1.0，GitHub 代码扫描直接吃 |

SARIF 里只放**可疑项**，不放通道清单——通道不是告警，塞进去会把告警计数搞乱。规则 id 稳定且是 ASCII：中文标题转不成 slug 时用文字摘要的哈希兜底，同一条规则每次都得到同一个 id，抑制和分类才做得起来。

**挂到 CI 上就这么写**

```yaml
- run: ipcsurface app.asar -o surface.md --fail-on high
- run: ipcsurface app.asar --format sarif -o ipcsurface.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ipcsurface.sarif
```

仓库自己的 `.github/workflows/ci.yml` 有两个 job：`check` 跑编译、用例、冒烟、自查；`signal` 专门验信号——干净靶子必须退 0，有问题的靶子必须退 2，再把 SARIF 传上去。第二个 job 不是在验工具，是在验「CI 到底能不能靠这些信号做判断」。



## 靶场

`examples/` 里有九个故意写坏的应用，源码是明的，答案在手上，跑完自己核分。

```bash
cd examples && bash build.sh
```

| 靶子 | 考的是什么 | 期望 |
| --- | --- | --- |
| `static` | 通道名全写死，藏一条 `__internal_sync` | 5 条通道、配对 5/5 |
| `dyn` | 四种算出来的名字 | 3 条进表，2 处留在「没看清」 |
| `obf` | 被压过的样子 | 认出强指纹，报告开头降级 |
| `obf2` | 字符串池 + 下标 | 4 条全认出 |
| `obf3` | 自解码函数 | 2 条，默认就还原 |
| `obf4` | 套两层自解码 | 1 条，剥两层 |
| `obf5` | 名字写在另一个文件里 | 2 条，靠全包常量表配上 |
| `bulk` | 八百条通道 | 报告不散架 |
| `native` | 带 `.node` 模块 | 说明「越界只在那些文件里」 |

另外有一组 **12 条对抗样本**，同一句 `vault:unlock` 换十二种写法（池子套池子、反转、base64、unicode、注释插在拼接处、方括号调用、名字放 json、模板套模板、`fromCharCode`、两跳变量……）。现在认出三处，另外九条如实标成「名字是算出来的」。

注意一件事：那三处用的是同一个名字，所以通道表里**去重后只有 1 条**。样本数和通道数不是一回事，写在这里免得下次自己看错。

这组样本比数字有用：它每次都在提醒，**认不出的时候不许装认出**。上一版就是它撞出来的——模板套模板会把输出拼坏，跨行模板摊平会让行号一路偏。

细节见 [`examples/README.md`](examples/README.md)。

---

## 自查

改完东西跑一遍，三十多项，全绿才算收工：

```bash
python scripts/selfcheck.py
```

查的是这些：版本号和 badge、README、CHANGELOG 对不对得上；schema 号；每条规则有没有对应用例；每个聚合字段的 `must_not` 有没有出处；真包实测数字（22,102 文件 / 41 条通道 / 221 候选）；报告里该有的话在不在；旧基线拦不拦得住；工作区干不干净、tag 推没推。

---

## 安全哲学

静态分析给不出答案，只能给材料。谁把它当判决书用，谁就是在赌。

所以这个工具在四处刻意慢下来：

**先说自己的可信度。** 报告第一节不是通道表，是这张表里每一层能证明什么。

**一条都没扫到的时候，顶在最前面喊。** 0 条字面通道不是「这包干净」，是「我这条路走不通」。那句「这份报告对有没有通道的答案是不知道」必须排在最前面，不能挂在末尾当免责声明。

**把看不懂的东西也列出来。** 算不出的名字不跳过、不猜、不归到「其他」。表达式原样贴出，位置原样标出。

**不替你做危险的决定。** 会执行目标代码的那一步（敲击）默认不动手；不会执行的那一步（自还原）默认开着。

---

## 它不干什么

- **不执行目标** —— 除了敲击那一步，而且那一步要你自己点名。
- **不还原全部字符串表** —— 路径、密钥这类普通常量不一定提得到，自己再 grep 一遍更稳。
- **不折叠算术** —— `7 * 60 * 1000` 不会变成 `420000`。
- **不做 native 二进制** —— 那是 Ghidra / Hopper / IDA 的活。
- **不查内存** —— 越界、泄漏不在静态语法里，真要看就下到 native 模块或者上运行时。
- **不写完整的 JS 解释器** —— 所以「函数拼 + 循环展开」「控制流平坦化」这类还原不了。
- **不把「对上」当成安全** —— 对上的是名字，不是行为。门后逻辑一律没审。

后面几条不是免责声明，是报告里的固定一栏。

---

## 开发

```bash
python -m unittest discover -s tests -v   # 129 个用例，只用标准库
bash scripts/smoke.sh                     # 把每条命令真跑一遍，十五项
python scripts/selfcheck.py                 # 三十多项自查，含真包实测
```

![冒烟跑完的样子](https://raw.githubusercontent.com/irrational51444/ipcsurface/main/docs/smoke.png)

单元测函数，冒烟测命令行，自查测「说的和做的对不对得上」。分开是因为它们挂的原因不一样：函数写错是逻辑问题，命令跑不通是参数问题，文档写得比实现漂亮是第三种问题。

**规则要配用例，而且这件事自己也得被检查。** `RULES` 是一张登记表，每条规则一个 id，测试套件里有一条 meta-test 扫全部用例，缺了就红。但要说清楚：meta-test 只保证「每条规则都有用例」，不保证「用例真的在测那条规则」——它防的是缺用例，不防用例无效。

---

## 为什么只有一个文件

两千一百多行，没有依赖。

因为它只做一件事：把上游已经算好的东西，按人能读的顺序摆出来，顺便把藏起来的名字尽量捞回来。这件事不值得一个框架。

REA 负责拆，这个脚本负责摆和还原，人负责判断。三段分开，每段都能单独验。

---

## 发布

当前 **0.32.0**。每个版本打一个 tag，全部版本在 [Releases](https://github.com/irrational51444/ipcsurface/releases)，逐条改动在 [CHANGELOG.md](CHANGELOG.md)。

```bash
git clone https://github.com/irrational51444/ipcsurface
cd ipcsurface
git checkout v0.32.0
python ipcsurface.py --version
```

近几版一句话一个：

| 版本 | 一句话 |
| --- | --- |
| 0.32.0 | 自查抓到通道口径不一致：报告 41 条，基线存了 52 |
| 0.30.0 | 补正向扫描：新字段靠「有没有登记」判定，不靠名字像不像 |
| 0.29.0 | 聚合字段登记表：第四次加聚合字段时检查先红 |
| 0.28.0 | 两个强度各管一件事：最好的多硬 vs 最薄的环节多薄 |
| 0.27.0 | 对上不再均质，每个名字带分侧强度 |
| 0.26.0 | 独立性改成十组判定表；基线自带 schema |
| 0.25.0 | `primary_action` 不能替代 `actions` |
| 0.24.0 | 对上分三档，41 → 31（那 10 条是误算） |
| 0.23.0 | 基线在 asar 路径上一直是哑的，这才接通 |
| 0.22.0 | schema 换号规则扩到枚举与结构 |
| 0.20.0 | 字面通道劈成逐字写着的和查表查出来的 |
| 0.17.0 | 认得常量对象，真包字面通道 0 → 41 |
| 0.9.0 | 一条通道都没扫到时，报告顶上先喊「我不知道」 |

版本号只在这种时候动：输出的东西变了、多认了一种写法、或者变的代价得让人知道。重构不动版本号。

---

## 许可

[MIT](LICENSE)
