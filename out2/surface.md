# Electron 能力面清单

- 目标：`C:\Users\irrational\Desktop\rea-lab\dyn.asar`
- 摘要 sha256：`3c53a523ea2dc68f…`
- 解析 2 个 JS 文件，182 个 AST 节点，失败 0 个

## 这份报告能信多少

有东西没看透：4 处通道名是算出来的、42 处关系没解析出来。
表里没写的，不等于没有。
- 没挂 native 模块，越界这类本来就不该出在 JS 这层，硬查是空转

## 窗口
- `src/main.js:12` preload=`preload.js` contextIsolation=True, nodeIntegration=False, preload=preload.js

## preload 暴露面
- 挂到 `window.ledger`，world=main，`src/preload.js:6`
  - `ledger.fixed` → `ledger:clear`  `src/preload.js:8`

## 通道表

| 通道 | 页面侧 | 主进程侧 | 配对 |
| --- | --- | --- | --- |
| `ledger:clear` | `src/preload.js:8` | `src/main.js:31` | 是 |

字面通道 1 条，两头都对上 1 条，动态通道 4 条

## 没看清的地方

这张表只能证明哪些看清了，不能证明没有什么。

- 通道名是算出来的不是写死的：`'ledger:' + 'shadow'`  `src/main.js:28`
- 通道名是算出来的不是写死的：`PREFIX + name`  `src/preload.js:7`
- 通道名是算出来的不是写死的：``ledger:${'tpl'}``  `src/main.js:29`
- 通道名是算出来的不是写死的：`makeChannel(op)`  `src/main.js:25`
- object-flow：partial，15 处没解析出来
- call-flow：partial，13 处没解析出来
- data-flow：partial，13 处没解析出来
- promise-ownership：partial，1 处没解析出来
- 这 8 类只覆盖了一部分：boundary、child-process、closure、configuration、event、request、resource-lifecycle、timer
- 混淆过的代码认不出来；打包压缩后的通道名会被当成算出来的值
- 动态 require、eval、拼接出来的路径，进不了这张表
- 内存层面它不看，越界、泄漏、重复释放要在运行时或者 native 那边查

## 可疑项
- [high] 一条 sender 校验都没有，任何页面都能调这些通道  `main 进程`
- [info] 没写 sandbox，走 Electron 默认值  `src/main.js:12`

> 依据静态语法，没有执行目标。「没写」不等于「没有」，也可能在别处设置。