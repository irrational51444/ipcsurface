# 对抗性视角：攻击者会怎么绕过这个工具

这份清单不是「已知会错」的补充，是另一件事：**主动站在绕过的一方，把能想到的写法挨个试一遍**，
记录哪些认得出、哪些认不出。

规则：

- 每一条「认得出」都要有用例守着；
- 每一条「认不出」都要写清为什么，别让读的人以为那条路是安全的；
- 清单不完整是常态，`docs/known-wrong.md` 里的是已经踩到的，这里是主动试的。

## 通道名怎么伪装

| 写法 | 认得出吗 | 为什么 |
| --- | --- | --- |
| `ipcMain.handle("literal", fn)` | ✅ | 字面量 |
| `ipcMain.handle("a" + "b", fn)` | ✅ | 纯字面量拼接，折叠 |
| `ipcMain["handle"]("x", fn)` | ✅ | 下标写法的成员 |
| `ipcMain["ha" + "ndle"]("x", fn)` | ✅ | 下标里也是字面量拼接 |
| `const K = "x"; ipcMain.handle(K, fn)` | ✅ | 同文件常量，查表 |
| `const {ipcMain: a} = require("electron"); a.handle("x", fn)` | ✅ | 解构重命名 |
| `require("electron").ipcMain.handle("x", fn)` | ✅ | 链式取成员 |
| ``ipcMain.handle(`tpl`, fn)`` | ✅ | 无插值的模板字符串 |
| `ipcMain.handle(String.fromCharCode(97, 98), fn)` | ❌ | 运行时才算得出，静态没有值 |
| ``ipcMain.handle(`tpl-${x}`, fn)`` | ❌ | 模板里有变量 |
| `ipcMain.handle(getName(), fn)` | ❌ | 函数返回值 |
| `for (const k in MAP) ipcMain.handle(k, fn)` | ❌ | 对象键枚举，见下 |
| `Object.keys(MAP).forEach(k => ipcMain.handle(k, fn))` | ❌ | 同上 |
| `eval("ipcMain.handle('x', fn)")` | ⚠️ | 认得出**是因为原始字符串还在文本里**，不是真解析了 eval |
| `new Function("...")` | ❌ | 同上，且我们不做动态求值 |

`eval` 那一行要特别说：它不是「我们看穿了 eval」，是「那段代码的字面形式恰好还躺在文件里」。
打乱一下字符串就认不出。别把它当成能力。

## 注册点怎么藏

| 写法 | 认得出吗 | 为什么 |
| --- | --- | --- |
| `exports.x = function(){}` 作为 handler | ✅ | 导出表 + 跨文件一跳 |
| `h = require("./m"); ipcMain.handle("x", h.save)` | ✅ | 跨文件，最多两跳 |
| `import { save } from "./m"; ipcMain.handle("x", save)` | ✅ | 导入表 |
| `e.exports.save = require("./impl").save` | ✅ | 纯转发，跟第二跳 |
| `e.exports.save = wrap(require("./impl").save)` | ❌ | 包了一层调用，不是转发 |
| `ipcMain.handle("x", this.onEvent)` | ✅ | 类方法名当符号跟进方法体 |
| `ipcMain.handle("x", obj[method])` | ❌ | 下标取方法，静态不知道 method |
| `setTimeout(() => ipcMain.handle("x", fn), 0)` | ⚠️ | 认得出，但「延迟注册」这个语义没建模 |

## 数据怎么绕

| 写法 | 认得出吗 | 为什么 |
| --- | --- | --- |
| 参数直接进危险调用 | ✅ | L1 零跳 |
| 参数经 `path.join` 进危险调用 | ✅ | L2，带锚定判定 |
| 参数写进 `C.field`，之后被读 | ⚠️ | 只报写入点和读点，**不证明**它们连着 |
| 参数存进 `Map` / `Set` / 数组再取出 | ❌ | 容器建模不做 |
| 参数经 Promise 链传递 | ❌ | 异步控制流不做 |
| 参数存进数据库/文件，下次进程启动再读 | ❌ | 跨进程状态，静态不可能 |

## Electron 语义上有哪些没验

这一节是**待人工核对**清单，不是结论：

- `ipcMain.handle` 和 `ipcMain.on` 的区别（invoke/单向）有没有影响「危险」判定——目前两者一视同仁；
- `contextBridge.exposeInMainWorld` 暴露的对象里，函数和值的边界怎么算——现在只报暴露了哪些名字；
- preload 在 `sandbox: true` 下的能力上限——现在没按 sandbox 值去收窄 preload 的分析；
- `webPreferences` 里的 `nodeIntegrationInSubFrames`、`enableRemoteModule` 是否该单独判——现在只判 nodeIntegration / contextIsolation；
- `protocol.registerFileProtocol` 之类自定义协议的风险档——现在只报「注册了」，不分档。

这几条要熟悉 Electron 安全的人逐条核。核之前，报告里不要把它们读成「已覆盖」。

## 怎么用这份清单

改分析器之前先跑一遍 `python -m unittest tests.test_ipcsurface.AdversarialShapeTests`。
加一条「认」就得加一条用例；改一条语义就得改这张表。

清单本身会过期——攻击手法在变，这里的每一条都只是「我想到的」。
