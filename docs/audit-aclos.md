# ACLOS 启动器：两条高危通道的利用链分析

分析对象：`C:\Program Files (x86)\ACLOS\Launcher\resources\app.asar`（121 MB，14598 文件）
工具版本：0.169.0
结论口径：**工具判定 + 人工读源码**。没验证的部分明确标出来。

## 一、工具检出

| 通道 | 危险调用 | 校验判定 | 人工结论 |
| --- | --- | --- | --- |
| `aiDebug:uploadLogArchive` | `existsSync`、`readFileSync` | 有校验 | **真高危**：任意读 + 任意 URL 上传 |
| `deleteCorruptFile` | `existsSync`、`unlinkSync` | 有校验 | **真高危**：任意路径删除 |
| `aiDebug:buildLogArchive` | `existsSync`、`readdirSync` | 有校验 | 误报（零参 handler + 内部路径） |
| `runDiagnose` | `existsSync` | 有校验 | 误报（形参被 `let` 遮蔽） |

后两条误报已修，修完工具只报前两条（0.169.0）。

## 二、`deleteCorruptFile` 的利用链

### 主进程侧

```js
// riotPatchSdk.js
a.on("deleteCorruptFile", (async (e, o) => {
  l.existsSync(o) ? (l.unlinkSync(o), ..., t = !0) : ...
```

- `on` 不是 `handle`：**单向 `send` 就能触发**，不需要 invoke；
- `o` 直接用，没有路径归属校验；
- 名字叫「删除损坏文件」，实现上不检查「是不是损坏文件」。

### 渲染侧有没有人调

```js
// assets/index.ae581287.js
C.send("deleteCorruptFile", s)
```

有真实调用点（文件损坏弹窗的「确认」分支）。

### 中间那一层：preload 暴露了什么

```js
// preload/common-browser-preload.js
const t = {
  sendToMain: ({channel: e, data: n}) => { s.send(e, n) },
  ...
}
contextBridge.exposeInMainWorld("EAPI", t)
```

**`sendToMain` 是任意通道透传**：renderer 传什么 channel，主进程就收到什么，
没有任何白名单。

### 链条

```
renderer
  → EAPI.sendToMain({channel: "deleteCorruptFile", data: <任意路径>})
  → ipcRenderer.send("deleteCorruptFile", <任意路径>)
  → a.on("deleteCorruptFile", o => l.unlinkSync(o))
  → 删除任意当前用户可删的文件
```

**唯一未确认的一环**：哪个窗口加载了 `common-browser-preload.js`。
asar 里没搜到 `preload:` 的静态配置（可能写在别处或由变量拼出来），这一层要跑起来动态看。

## 三、`aiDebug:uploadLogArchive` 的利用链

```js
s.handle("aiDebug:uploadLogArchive", (async (e, o) => {
  const {filePath: r, uploadUrl: n, headers: t, sizeBytes: s} = o || {}
  if (!r || !n || !f.existsSync(r)) return ...     // 只查存在
  const e2 = f.statSync(r).size
  if (e2 !== (s || e2)) return ...                 // 只查大小一致
  const c = f.readFileSync(r)                       // ← r 完全可控
  const i = await g({method: "put", url: n, headers: t, data: c})  // ← n、t 也完全可控
```

三个参数全部来自 IPC：读哪个文件、传到哪、带什么头。

校验只有「文件存在」和「大小一致」，**没有路径归属校验** —— 任意可读文件都能读出来，
PUT 到攻击者控制的地址。

它挂在 `aiDebug:` 前缀下，渲染侧没有搜到直接调用点（`aiDebug` 在渲染包里只是
Vue 组件的 ref 名）。但**只要 `web-ipc-preload.js` 或 `common-browser-preload.js`
被加载到某个能被注入内容的 webview，`webviewSend` / `sendToMain` 就是现成的透传口**。

`uploadLogArchive` 是 `handle`（invoke），不是 `send`，所以需要一条能发 invoke 的
透传口。`common-browser-preload.js` 只有 `send`，`web-ipc-preload.js` 也只有 `send`。
**这一步没找到现成的 invoke 透传**——要挂它得有别的入口。

## 四、这次分析暴露的工具问题

1. **形参列表解析错了**：`(async (e, o) => {...})` 外层括号被当成形参列表，
   两个形参落在 depth 2 全丢；旧版还会一路扫到最外层 `)`，把整个函数体当形参。
   已修（0.169.0）。
2. **`let` 遮蔽没处理**：`(e => { let e = h(); ... })` 里形参被局部声明盖掉。
   已修。
3. **preload 暴露面没建模**：工具能列出 `exposeInMainWorld` 的名字
   （`EAPI`、`AclosApi`、`jsbridge`…），但**不分析这些对象里的方法是不是任意通道透传**。
   `sendToMain({channel, data})` 这种形态是最危险的一类，现在只能人肉读。

## 五、还没做的事

- 确认哪个窗口加载了 `common-browser-preload.js`（要跑起来看 `webContents.getLastWebPreferences()`）；
- `webviewSend` 的调用方是否可控（webview 里加载的页面是第三方）；
- `jsbridge.call({namespace, funcName, params})` 走 `LoginVerifyWebviewCall`，
  主进程侧有没有按 namespace/funcName 白名单过滤——没查。
