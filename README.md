# ipcsurface

**把一个 Electron 应用的能力面，压成一页纸。**

[![ci](https://github.com/irrational51444/ipcsurface/actions/workflows/ci.yml/badge.svg)](https://github.com/irrational51444/ipcsurface/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-black)](LICENSE)
[![python](https://img.shields.io/badge/python-3.9%2B-black)](pyproject.toml)

---

## 它解决的问题

Electron 应用的能力，一半在主进程里。渲染进程碰不到文件、碰不到命令、碰不到网络底层，全都要过 `ipcMain` 那几扇门。

门是 preload 拿 `contextBridge` 开出来的。开的时候没人记账，半年后就没人数得清有多少扇、哪扇通向哪里、哪扇是谁加的。

审计要找的从来不是「有没有 IPC」，是这三件事：

1. 页面能碰到什么 —— `contextBridge` 往 `window` 上挂了什么，每个成员通向哪条通道
2. 每扇门两头落在哪 —— 页面侧发起在哪一行，主进程接住又在哪一行，配没配上
3. 哪几扇开得不对 —— `nodeIntegration`、`contextIsolation`、sender 校验，以及名字像后门的通道

前两件事有工具能查：[REA](https://github.com/morluto/rea) 能把一个 `.asar` 静态解析成上兆的证据 JSON。第三件事得有人看。

问题在中间那段：JSON 里什么都有，人翻不动。

这个脚本就干这一段。

## 两种精度

同一个工具，两种输入。糙的那个不用装任何东西。

| 输入 | 需要什么 | 准到什么程度 | 适合什么时候 |
| --- | --- | --- | --- |
| `app.asar` | 只要 Python | 字符串级：只认写死的名字 | 刚拿到包，想知道值不值得认真查 |
| REA Evidence | Python + REA | 语法级：建图、跟作用域、带行号 | 真要出结论 |

粗扫不是简化版的静态分析，是另一回事：它不建语法树，跟着代码走不通，字符串一拼就断。它能回答「这包看着像不像有事」，回答不了「这扇门通哪儿」。

两边的报告都长一个样，开头都先说自己能信多少。

## 三条原则

**只搬证据，不下结论。** 每一条断言后面都跟着 `文件:行号`。工具不告诉你「这里有漏洞」，它告诉你「这条通道接在 main.js:73，名字里有个 `__internal`」。

**没看清的地方要写在前面。** 静态分析的输出最危险的形态不是「漏了」，是「看起来很干净」。所以报告的第一节不是通道表，是这份报告能信多少。

**不猜。** 表达式解不出来就原样贴出来，包括反引号和加号。

## 安装

需要 Python 3.9+，只用标准库。

```bash
pip install .
```

或者不装，直接跑：

```bash
python ipcsurface.py --help
```

只有想用语法级分析时才需要 REA：

```bash
npm install -g rea-agents
```

## 快速开始

**糙的**，一个包换一页纸，零依赖：

```bash
ipcsurface app.asar surface.md
```

写完终端只留一行，人不用打开文件就知道要不要看：

```
wrote surface.md — 5 条通道，2 条可疑，0 处名字是算的
```

**准的**，两步：

```bash
rea analyze-javascript-application app.asar \
    --detail summary --evidence_output evidence

ipcsurface evidence surface.md
```

**比两个版本**，升级后多了哪扇门：

```bash
ipcsurface v1/evidence --diff v2/evidence -o change.md
```

常用参数：

| 参数 | 作用 |
| --- | --- |
| `-o, --out` | 写到文件；不给就打到标准输出 |
| `--format json` | 机器可读，方便接进别的流程 |
| `--fail-on high` | 出现该级别及以上问题时退出码 2，可以挂 CI |
| `--diff OTHER` | 把输入当旧版，和另一份 Evidence 比 |

`--fail-on` 的用法：

```bash
ipcsurface evidence surface.md --fail-on high || echo "有高危，人工看一眼再合"
```

## 输出长什么样

下面这段是真跑出来的，不是示意。

```markdown
## 这份报告能信多少

有东西没看透：195 处关系没解析出来。
表里没写的，不等于没有。
- 没挂 native 模块，越界这类本来就不该出在 JS 这层，硬查是空转

## preload 暴露面
- 挂到 `window.ledger`，world=main，`src/preload.js:4`
  - `ledger.add` → `ledger:add`  `src/preload.js:5`
  - `ledger.sync` → `ledger:__internal_sync`  `src/preload.js:9`

## 通道表

| 通道 | 页面侧 | 主进程侧 | 配对 |
| --- | --- | --- | --- |
| `ledger:__internal_sync` | `src/preload.js:9` | `src/main.js:73` | 是 |
| `ledger:add` | `src/preload.js:5` | `src/main.js:44` | 是 |

## 可疑项
- [high] 一条 sender 校验都没有，任何页面都能调这些通道  `main 进程`
- [medium] 通道名带隐藏意味：ledger:__internal_sync  `src/preload.js:9`
```

那串 195 是这包本身的未解析数。数字大不代表工具差，代表它没假装自己全看见了。

## 靶场

`examples/` 里放着两个故意写坏的应用。源码是明的，答案在手上，跑完自己核分。

```bash
cd examples && bash build.sh
```

**static-asar** —— 通道名全写死，其中一条是故意藏的 `ledger:__internal_sync`，带一串 token，没有任何 sender 校验。

期望：5 条字面通道、5 个暴露成员、配对 5/5、五条行号一条不差。

**dyn-asar** —— 通道名是算出来的，四种拼法：

| 位置 | 写法 |
| --- | --- |
| `src/main.js:25` | `makeChannel(op)` |
| `src/main.js:28` | `'ledger:' + 'shadow'` |
| `src/main.js:29` | `` `ledger:${'tpl'}` `` |
| `src/preload.js:7` | `PREFIX + name` |

期望：通道表里只剩 `ledger:clear` 一条。另外四处进不了表，但必须原样出现在「没看清的地方」，带表达式和行号。

这个靶子是专门为「动态生成」这条缺点建的。在补上之前，这四行会被静静吞掉，报告看着干净——干净才是危险的。

细节见 [`examples/README.md`](examples/README.md)。

## 安全哲学

静态分析给不出答案，只能给出材料。谁把它当判决书用，谁就是在赌。

所以这个工具在两个地方刻意慢下来：

**它先说自己的可信度。** 每个包里都有解析不出来的东西——对象流转、动态调用、闭包捕获，这些在语法层面就是模糊的。报告开头把总数和分类摆出来，读者知道自己手里这份东西有多重。

**它把看不懂的东西也列出来。** 遇到动态拼接的通道名，不会跳过、不会猜、不会归到「其他」。表达式原样贴出，位置原样标出：

```markdown
- 通道名是算出来的不是写死的：`makeChannel(op)`  `src/main.js:25`
- 通道名是算出来的不是写死的：`PREFIX + name`  `src/preload.js:7`
```

这行字的意思是：这里有一扇门，但我不知道它通哪儿。知道有人不知道，比装作全都知道有用。

## 它不干什么

- **不执行目标。** 全部结论来自惰性语法。运行时的注册、分支、默认值都不管。
- **不还原字符串表。** 路径、密钥这类普通常量不一定提得到。自己再 grep 一遍更稳。
- **不折叠算术。** `7 * 60 * 1000` 不会变成 `420000`。
- **不做 native 二进制。** 那是 Ghidra / Hopper / IDA 的活，REA 也只是转发。
- **不查内存。** 越界、泄漏、重复释放这些在静态语法里不存在。JS 这层本来也不该有，真要看就得下到 native 模块或者上运行时。
- **不看混淆过的代码。** 字符串被拼起来、`require` 路径算出来、代码被打包压过，这些都进不了表。

后面两条不是免责声明，是报告里的固定一栏。

## 开发

```bash
python -m unittest discover -s tests -v
```

十六个用例，只用标准库，不需要装 REA。asar 的解析器在测试里用手搓的包验证，靶子应用在 `examples/`。

## 为什么只有一个文件

五百行，没有依赖。

因为它只做一件事：把上游已经算好的东西，按人能读的顺序摆出来。这件事不值得一个框架。

REA 负责拆，这个脚本负责摆，人负责判断。三段分开，每段都能单独验。

## 许可

[MIT](LICENSE)
