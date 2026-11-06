# ipcsurface

Electron 应用的能力都摊在 preload 上，通道一条条加上去，过半年就没人说得清哪条是谁开的。

REA 能把一个 asar 静态解析成上兆的 Evidence JSON，线索全在里面，但人翻不动。这个脚本把那坨证据压成一页：

- preload 往 `window` 上挂了什么，每个方法通向哪条通道
- 每条通道两头各落在哪个文件哪一行，配没配上
- 照着几条硬规则点出该盯的地方：`nodeIntegration`、`contextIsolation`、sender 校验、名字像后门的通道

它不猜。每条结论后面都带着证据位置。

## 装

先有 REA：

```bash
npm install -g rea-agents
```

然后装这个：

```bash
pip install .
```

不装也行，`python ipcsurface.py ...` 直接跑。只用标准库，没有依赖。

## 用

```bash
# 1. 拿证据
rea analyze-javascript-application app.asar --detail summary --evidence_output evidence

# 2. 压成一页
ipcsurface evidence surface.md
```

选项：

| 参数 | 作用 |
| --- | --- |
| `-o, --out` | 写到文件，不给就打到标准输出 |
| `--format json` | 输出机器可读的摘要 |
| `--fail-on high` | 出现该级别及以上问题时以退出码 2 结束，可以挂 CI |

## 输出长这样

```markdown
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

## 它不干什么

- 不执行目标。全部结论来自惰性语法，运行时的注册、分支、默认值都不管。
- 不还原字符串表。路径、密钥这类普通常量不一定提得到，自己再 grep 一遍更稳。
- 不折叠算术。`7 * 60 * 1000` 不会变成 `420000`。
- 不做 native 二进制。那是 Ghidra / Hopper / IDA 的活，REA 也只是转发给它们。
- 不查内存。越界、泄漏、重复释放这些在静态语法里根本不存在，得上运行时或者去反编译 native 模块。
- 不看混淆过的代码。字符串被拼起来、`require` 路径是算出来的、代码被打包压过，这些都进不了表。

最后两条不是免责声明，是报告的固定一栏。输出里那块「没看清的地方」会把没解析出来的条数按类摆出来，因为一张表只能证明看清了什么，不能证明没有什么。

## 来由

拿自己写的一个小 Electron 应用当靶子试 REA，顺手把对账的活做成了脚本。

源码是我写的，答案我有，所以能核对：5 条通道、5 个暴露成员、窗口的安全设置，行号一条不差，连故意藏的 `ledger:__internal_sync` 和那串 token 都被挖出来了。

但结论还是得人下。脚本只负责把位置摆到你面前。

MIT。
