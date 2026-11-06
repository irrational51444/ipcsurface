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

审计要找的从来不是「有没有 IPC」，是这三件事：

1. 页面能碰到什么 —— `contextBridge` 往 `window` 上挂了什么，每个成员通向哪条通道
2. 每扇门两头落在哪 —— 页面侧发起在哪一行，主进程接住又在哪一行，配没配上
3. 哪几扇开得不对 —— `nodeIntegration`、`contextIsolation`、sender 校验，以及名字像后门的通道

有工具能把 `.asar` 拆成上兆的证据：[REA](https://github.com/morluto/rea)。问题在中间那段——JSON 里什么都有，人翻不动。

这个脚本就干这一段。

## 三种输入

| 输入 | 需要什么 | 准到什么程度 | 适合什么时候 |
| --- | --- | --- | --- |
| `app.asar` | 只要 Python | 字符串级，带五道还原 | 刚拿到包，想知道值不值得认真查 |
| REA Evidence | Python + REA | 语法级：建图、跟作用域、带行号 | 真要出结论 |
| `x.dll` / `x.exe` | 只要 Python | 导入表：只说引了哪些外头函数 | 往下走一层，看它靠什么干活 |

三种都出同样的报告，同样一节「这份报告能信多少」在最前面。

## 名字藏起来了怎么办

真实应用发出去是打包压过的，`ipcMain.handle('vault:unlock')` 会变成 `a.b(c[3],d)`。这就是字符串级扫描的死穴——我拿一个两万两千文件的真包试过，字面通道认出来 0 条。

但这个 0 不是死的。五道还原，全在粗扫里自动跑：

| 手法 | 长什么样 | 怎么还原 |
| --- | --- | --- |
| 字符串池 | `var _0x=['vault:unlock',…]` 配 `_0x[0]` | 找到全是字符串的数组，下标换回字面量 |
| 死拼接 | `'ledger:' + 'shadow'` | 两头都是字面量，直接折成一段 |
| 模板串 | `` `ledger:${'tpl'}` `` | 插值是写死的，摊平 |
| 常量 | `const PREFIX='ledger:'` 配 `PREFIX + name` | 前缀代回去，露出 `"ledger:" + name` |
| 跨文件常量 | 名字写在 `channels.js`，`main.js` 里 `handle(CHANNEL)` | 先收一遍全包的字符串常量建表，第二遍扫的时候查表 |
| 自解码函数 | `_d('\x71\x66…')`，函数体里逐字符异或 | 认函数体的形状，用纯 Python 算。套几层剥几层 |
| 打捞 | 调用点认不出了，名字还在字符串里 | 抽出所有 `前缀:名字` 的字面量，去噪，按位置列出来 |

最后一道是兜底：两万两千个文件里捞到 221 个候选。但直接给你 221 个没用——大半是第三方库的。所以捞的时候顺手分家：哪个文件是自己写的、哪个是 `node_modules` 里的、哪个是测试。分完之后 221 里只有 51 个是这应用自己的，全是 `dsh-desktop:clipboard-image-read`、`dsh-desktop:device-info` 这种一看就该看的名字。

从零翻起、和拿着一张 221 行的名单翻、和拿着一张 51 行的名单翻，是三件不同的事。后面两档差的就是这一道分家。

自解码那一道默认开着，因为它**不执行目标里的任何代码**——只认几种形状自己算，认不出就放弃。想关加 `--no-eval`。

## 安装

Python 3.9+，只用标准库。

```bash
pip install .
```

不装也行，`python ipcsurface.py --help` 直接跑。只有想用语法级分析才需要 REA：`npm install -g rea-agents`。

## 发布

当前 **0.27.0**。每个版本打一个 tag，全部版本在 [Releases](https://github.com/irrational51444/ipcsurface/releases) 那一页，逐条改动在 [CHANGELOG.md](CHANGELOG.md)。

```bash
git clone https://github.com/irrational51444/ipcsurface
cd ipcsurface
git checkout v0.27.0    # 想看某一个版本就切到它的 tag
python ipcsurface.py --version
```

近几版各解决了什么，一句话一个：

| 版本 | 一句话 |
| --- | --- |
| 0.11.0 | 真包运行时跑通了：粗扫 0 条，探针读到 27 条 |
| 0.10.0 | 对抗测试照出来的三处：行号一直有偏差、unicode 和方括号写法认不出 |
| 0.9.0 | 一条通道都没扫到的时候，报告顶上先喊「我不知道」，不装干净 |
| 0.8.0 | 解包改成按需 mmap 切片，峰值 498 MB → 411 MB |
| 0.7.1 | 混淆那六条先探子串再起正则，真包 3.9 秒 → 3.5 秒 |
| 0.7.0 | 混淆识别和打捞都改在字节上做，5.9 秒 → 3.9 秒 |
| 0.6.1 | 跨文件常量：通道名写在 a.js、用在 b.js 也配得上 |
| 0.6.0 | 把藏起来的名字尽量捞回来：字符串池、死拼接、模板、自解码函数、打捞兜底 |

版本号只在这种时候动：输出的东西变了、多认了一种写法、或者变的代价得让人知道。重构不动版本号。

## 快速开始

**糙的**，一个包换一页纸：

```bash
ipcsurface app.asar surface.md
# wrote surface.md — 5 条通道，2 条可疑，0 处名字是算的
```

**准的**，两步：

```bash
rea analyze-javascript-application app.asar --detail summary --evidence_output evidence
ipcsurface evidence surface.md
```

**只报新冒出来的**，老问题不重复吵：

```bash
ipcsurface evidence --write-baseline base.json -o surface.md   # 第一次
ipcsurface evidence --baseline base.json -o surface.md --fail-on high
```

审计工具不解决噪音就没人用。一上来二十条高危，看三遍就麻木了。基线让「这次改动引入了什么」成为唯一的问题。

**比两个版本**，升级后多了哪扇门——两边可以直接给 asar：

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
| `--format json` | 三种输入都支持 |
| `--fail-on high` | 出现该级别及以上问题时退出码 2，可以挂 CI |
| `--diff OTHER` | 把输入当旧版，和另一份比 |
| `--baseline FILE` | 只报基线里没有的发现 |
| `--write-baseline FILE` | 把这次的发现存成基线 |
| `--no-eval` | 关掉自解码还原。默认开着 |
| `--runtime PROBE` | 并入运行时探针的结果 |
| `--poke POKE` | 并入敲击结果 |
| `--all` | 不截断 |

## 输出长什么样

![真实输出：对一个 5 条通道的应用跑出来的报告](https://raw.githubusercontent.com/irrational51444/ipcsurface/main/docs/preview.png)

上面这张是真跑出来的，`examples/build.sh` 跑一遍就能自己复现。报告的结构固定：先说能信多少，再列证据，最后给下一步。

## 让程序自己说

静态只能猜。这两步是问。

```bash
cd probe && npm install

# 读登记表：注册了哪些通道、窗口真实的 sandbox 值
node probe/run.js 应用目录 6 > probe.json

# 真敲一遍：每条通道喂空值、空对象、十万字符、null
node probe/poke.js 应用目录 6 > poke.json

ipcsurface evidence --runtime probe.json --poke poke.json -o surface.md
```

读登记表那步，混淆是没用的——代码在磁盘上乱名，跑起来内存里是明文。

敲击那步，报告会分出两栏：**照收的**（喂什么都不看还返回结果，最值得看）和**抛错的**（可能人家本来就该拒）。静态分析只能告诉你门存在，敲一下才知道门后面有没有人看门。

**注意**：敲击会真的执行目标代码。只对自己的靶子或明确授权的程序用。

## 拿一个真包从头走到尾

不是演习。一个 **213 MB、22,102 个文件**的真实 Electron 应用：

| 步骤 | 用时 | 结果 |
| --- | --- | --- |
| 粗扫 | 4.4 秒 | 字面通道 41 条，打捞到 221 个候选 |
| 语法级 · 全量 | **十分钟没跑完** | 放弃，换下面的方式 |
| 语法级 · 挑文件 | 54 秒 | 产出 259 MB 证据 |
| 读证据 | 2.4 秒 | 一页报告 |
| 基线 / 门禁 | 2.5 秒 | 两次跑压掉旧的 |

三件事，都写进了代码里：

**全量语法级分析在大包上跑不动。** 读一遍和读懂一遍是两回事：两万多个文件读进来 0.3 秒，但给每个文件建语法树、连引用、推数据流，是另一笔账。正确姿势是先粗扫打捞，挑出可疑文件，再用 `--source-path` 精查那一个。

**单文件分析缺上下文，就别硬下结论。** 只喂一个文件时看不到窗口代码，那「一条 sender 校验都没有」这句话就不成立。这一条原来是误报，现在加了条件。

**证据大不等于慢。** 259 MB 的 JSON，读一遍 2.4 秒。

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
| `bulk` | 八百条通道 | 报告不散架，八十行 |
| `native` | 带 `.node` 模块 | 说明「越界只在那些文件里」 |
| `map` | 带 sourcemap | 从 `sourcesContent` 翻回源码 |

细节见 [`examples/README.md`](examples/README.md)。

## 安全哲学

静态分析给不出答案，只能给材料。谁把它当判决书用，谁就是在赌。

所以这个工具在三处刻意慢下来：

**先说自己的可信度。** 每个包里都有解析不出来的东西。报告第一节不是通道表，是这份报告能信多少。

**把看不懂的东西也列出来。** 遇到算不出的名字，不跳过、不猜、不归到「其他」。表达式原样贴出，位置原样标出。这行字的意思是：这里有一扇门，但我不知道它通哪儿。

**不替你做危险的决定。** 会执行目标代码的那一步（敲击），默认不动手；不会执行的那一步（自解码），默认开着。

## 它不干什么

- **不执行目标** —— 除了敲击那一步，而且那一步要你自己点名。
- **不还原字符串表** —— 路径、密钥这类普通常量不一定提得到，自己再 grep 一遍更稳。
- **不折叠算术** —— `7 * 60 * 1000` 不会变成 `420000`。
- **不做 native 二进制** —— 那是 Ghidra / Hopper / IDA 的活。
- **不查内存** —— 越界、泄漏、重复释放不在静态语法里。JS 这层本来也不该有，真要看就下到 native 模块或者上运行时。
- **不写完整的 JS 解释器** —— 那是另一个项目。所以「函数拼 + 循环展开」「控制流平坦化」这类还原不了。

后面几条不是免责声明，是报告里的固定一栏。

## 开发

```bash
python -m unittest discover -s tests -v   # 116 个用例，只用标准库
bash scripts/smoke.sh                     # 把每条命令真跑一遍，十五项
```

![冒烟跑完的样子](https://raw.githubusercontent.com/irrational51444/ipcsurface/main/docs/smoke.png)

单元测测函数，冒烟测命令行。分开是因为它们挂的原因不一样——函数写错是逻辑问题，命令跑不通是参数问题，后者单元测看不见。门禁那两项还要求特定退出码：压过的包必须返回 2，干净的必须返回 0。跑通不算数，拦得住才算。

## 为什么只有一个文件

一千五百行，没有依赖。

因为它只做一件事：把上游已经算好的东西，按人能读的顺序摆出来，顺便把藏起来的名字尽量捞回来。这件事不值得一个框架。

REA 负责拆，这个脚本负责摆和还原，人负责判断。三段分开，每段都能单独验。

## 许可

[MIT](LICENSE)
