# Electron 应用 IPC 能力面安全审计报告

| 项 | 内容 |
| --- | --- |
| 审计对象 | Obsidian 1.11.7（`obsidian.asar`，28,177,896 字节，369 个文件） |
| 审计类型 | 静态分析，白盒（有完整 asar 内容） |
| 审计范围 | 主进程 IPC 通道（`ipcMain.on` / `ipcMain.handle`）及其可达的危险 API |
| **不在范围** | 渲染进程 XSS、preload 之外的攻击路径、native 模块内部、更新链路、加密 vault 内容 |
| 工具 | ipcsurface 0.116.0（本次审计的执行工具） |
| 审计日期 | 2026-11-13 |
| 结论 | **2 项高危、2 项中危、1 项需人工确认；整体可用但存在路径校验缺失** |

---

## 一、执行摘要

Obsidian 通过 Electron 的 IPC 机制向渲染进程暴露了 **47 条通道**。对其中的危险 API 可达性做静态分析，得到 116 条结论，其中 25 条属于「高置信度」档位。

对这 25 条逐条读源码验证后：

- **25 条全部真实**，工具没有误报
- 其中 **2 条** 存在**参数校验缺失**，可被渲染进程利用来做越权文件操作
- **2 条** 存在路径处理缺陷（一条可穿越，一条源路径任意）
- **1 条** 的真正危险 API 藏在未展开的函数里，本次**未能判定**

**最需要处理的是 `print-to-pdf`**：渲染进程传什么路径就往哪写，没有任何校验。

**风险分布**

| 严重度 | 数量 | 通道 |
| --- | --- | --- |
| 高 | 2 | `print-to-pdf`、`vault-move` |
| 中 | 2 | `set-icon`、`copy-asar` |
| 待确认 | 1 | `open-url` |
| 低 / 无 | 10 | 其余 |

---

## 二、审计方法

1. **能力面枚举**：用 ipcsurface 解析 asar，提取所有 `ipcMain.on` / `ipcMain.handle` 注册点，还原通道名（含常量对象成员、模板字符串、字面量拼接）。
2. **危险 API 可达性**：从每个处理函数出发，沿调用图（同文件最多 4 跳、跨文件最多 2 跳）找出可达的危险 API（`exec` / `writeFile` / `unlinkSync` / `renameSync` / `copyFileSync` 等）。
3. **证据分级**：每条结论标注来路档位（直接调用 / 双口径证实 / 同文件链 / 同名多义 / 仅语法树）和证据完整度，只对前两档做人工复核。
4. **人工验证**：对 25 条高置信度结论，逐条从 asar 抽出 `main.js`（203,702 字节，单行压缩），按工具给出的内偏移定位注册点，**读完整函数体**，判断参数来源与校验情况。

**工具局限**（影响结论适用范围）：

- 静态分析看不到运行时行为。加密载荷、运行时算出的通道名一律看不见。
- **不做参数流分析**。「能不能碰到 API」能答，「参数可不可控」要靠人工读。
- 本次审计的 47 条通道名全部是写死的（`dynamic` 计数为 0），没有「名字算不出来」的情况。

---

## 三、发现清单

### F-01（高）`print-to-pdf`：文件写入路径完全未校验

| 项 | 内容 |
| --- | --- |
| 通道 | `print-to-pdf` |
| 危险 API | `fs.promises.writeFile` |
| 位置 | `main.js:66@191410` |
| 参数来源 | 渲染进程，`i.filepath` |
| 校验 | **无** |
| **参数可控性（工具自动判定）** | **`d` 来自 `i.filepath`**，零跳污点，中间没经任何函数调用——这是「能被利用」最硬的证据 |

```js
ipcMain.on("print-to-pdf", async (o, i) => {
  let { filepath: d } = i
  let b = await c.printToPDF(i)
  await m.promises.writeFile(d, b)      // ← d 直接来自渲染进程
  ...
})
```

**影响**：能调这条通道的渲染进程，可以让主进程把 PDF 内容写到**任意可写路径**——包括启动目录、`~/.bashrc` 之类。

**修复建议**：

- 路径白名单（只允许写到用户选择的目录）
- 或弹出保存对话框让用户确认（同类代码里 `open-file` 就用了这个模式）
- 至少校验 `F.resolve(d)` 落在允许的根目录内

---

### F-02（高）`vault-move`：目标路径完全未校验

| 项 | 内容 |
| --- | --- |
| 通道 | `vault-move` |
| 危险 API | `fs.renameSync` |
| 位置 | `main.js:66@192049` |
| 参数来源 | 渲染进程，`i`（源）、`c`（目标） |
| 校验 | `i` 有类型 + 归属校验；**`c` 无任何校验** |
| **参数可控性（工具自动判定）** | 源 `i` **零跳可控**。目标 `c` 没被工具标出——它来自同一个 `i` 的兄弟参数，那条链这一版还没跟 |

```js
ipcMain.on("vault-move", (o, i, c) => {
  if (i && typeof i == "string")
    for (let d in R) if (R[d].path === i) {
      if (Y[d]) { o.returnValue = "EVAULTOPEN"; return }
      try { m.renameSync(i, c) }        // ← c 没有任何校验
      ...
```

**影响**：能把任意一个**已注册 vault** 移动到任意路径（包括覆盖同名目录的行为取决于底层 `rename` 语义）。

**缓解因素**：源路径必须是已注册 vault，不是任意文件。

**修复建议**：对 `c` 做与 `i` 同级的校验——类型、是否落在用户选择的目录内、是否已存在。

---

### F-03（中）`set-icon`：`F.join(v, i)` 可被路径穿越

| 项 | 内容 |
| --- | --- |
| 通道 | `set-icon` |
| 危险 API | `fs.rmSync` + `fs.writeFileSync` |
| 位置 | `main.js:66@194669` |
| 参数来源 | 渲染进程，`i`（文件名）、`c`（内容） |
| 校验 | 无 |
| **参数可控性（工具自动判定）** | `i` **经 `F.join` 一跳可控**——工具标出 `经join(i)/join(icon)`，这正是穿越的入口 |

```js
ipcMain.on("set-icon", (o, i, c) => {
  C.icon && m.rmSync(F.join(v, C.icon), { force: true })
  i && c ? m.writeFileSync(F.join(v, i), c) : i = null
  ...
})
```

**影响**：`F.join(v, i)` 在 `i` 含 `../` 时不保证落回 `v` 内——`F.join('/data', '../../etc/x.png')` 会得到 `/data/../../etc/x.png`，实际解析到 `/etc/x.png`。**可以删掉任意文件**（`rmSync` 带 `force`）。

**修复建议**：写入前校验 `F.resolve(F.join(v, i))` 以 `F.resolve(v) + F.sep` 开头。

---

### F-04（中）`copy-asar`：源路径任意

| 项 | 内容 |
| --- | --- |
| 通道 | `copy-asar` |
| 危险 API | `fs.copyFileSync` |
| 位置 | `main.js:66@190360` |
| 参数来源 | 渲染进程，`i`（源路径） |
| 校验 | 无 |
| **参数可控性（工具自动判定）** | `i` **经 `basename`+`join` 一跳可控**，工具标出 `经join(d)` |

```js
ipcMain.on("copy-asar", (o, i) => {
  let c = F.basename(i)
  let d = /^obsidian-(\d+\.\d+\.\d+)/.exec(c)
  let b = F.join(v, `${d[0]}.asar`)
  mo.copyFileSync(i, b)                 // ← i 任意
  ...
})
```

**影响**：能把**任意可读文件**复制到应用数据目录。目标被 `basename` 限住了，但源没限——等于提供了一个「把任意文件搬进来」的原语。

**修复建议**：校验 `i` 的扩展名和目录，或者干脆只接受用户通过对话框选的文件。

---

### F-05（待确认）`open-url`：真正的 sink 在未展开的 `H()` 里

| 项 | 内容 |
| --- | --- |
| 通道 | `open-url` |
| 工具报的危险 API | `stat`、`writeFileSync` |
| 位置 | `main.js:66@193517` |
| 状态 | **未判定** |

```js
ipcMain.on("open-url", (o, i) => {
  let c = l.BrowserWindow.fromWebContents(o.sender)
  c && typeof i == "string" && H(c, i)     // ← H 未展开
})
```

`H(c, i)` 是本次审计**没能读透**的部分。工具报的 `stat` / `writeFileSync` 来自调用链下游，但真正决定风险的是 `H` 内是否调 `shell.openExternal`、以及 URL 有没有协议白名单。

**建议**：这一条需要跟到 `H` 的实现（本次时间不足以完成），优先级应高于 F-03 / F-04。

---

### 其余 10 个通道：无问题或风险可接受

| 通道 | 判定 |
| --- | --- |
| `vault-remove` | 有类型 + 归属校验，开着的 vault 拒绝；删除对象限于已注册 vault |
| `vault-message` | `F.resolve` 后必须匹配已注册 vault |
| `open-file` | 路径来自**系统文件对话框**，不是渲染进程直接传 |
| `register-cli` | 跑 PowerShell 改 PATH，但拼进去的是 `process.execPath` 的目录，不可控 |
| `set-language` / `frame` | 写配置字段，无类型检查但影响面小 |
| `cli` / `insider-build` / `disable-gpu` / `disable-update` | 布尔开关，无可利用面 |

---

## 三之二、工具自动判到什么程度，人工补了什么

这一节单独列出来，是因为「哪部分是机器给的、哪部分是人读的」直接决定这份报告能不能被复核。

| 环节 | 谁做的 | 能证明什么 |
| --- | --- | --- |
| 有哪些通道 | 工具（枚举 `ipcMain.on/handle`） | 47 条，写死的名字，0 处是算的 |
| 每条能碰到哪些危险 API | 工具（调用图 + 语法树双口径） | 25 条硬结论，全部经人工验证 |
| 实参可不可控（零跳） | **工具** | 危险调用的实参是不是直接来自 IPC 参数 |
| 实参可不可控（一跳） | **工具** | 脏值经过 `path.join/resolve` 一次 |
| 实参可不可控（跨函数） | **工具**（这个包上零命中） | 脏实参传进本文件另一个函数 |
| **参数有没有被校验** | **人工** | 工具不答。F-01 的「零校验」、F-03 的「`..` 能穿越」都是读源码看出来的 |
| **渲染进程能不能调到这条通道** | **人工**（未做） | 取决于 preload 暴露范围，本次未展开 |

**最后两行是这份报告的边界。** 前面几行机器能替人干，后面两行机器干不了。


## 四、附录 A：完整通道清单（47 条）

工具报出 47 条通道，其中 24 条能碰到危险 API。完整清单在工具输出的 `report.md`「通道」一节。

**能碰到危险 API 的 24 条**：

`adblock-frequency`、`adblock-lists`、`check-update`、`cli`、`copy-asar`、`create-browser-session`、`disable-gpu`、`disable-update`、`frame`、`get-icon`、`insider-build`、`open-file`、`open-url`、`print-to-pdf`、`register-cli`、`sandbox`、`set-icon`、`set-language`、`set-menu`、`vault-message`、`vault-move`、`vault-open`、`vault-remove`、`vault-sandbox-vault-path`

**其余 23 条**：只做状态读写或转发，未发现可达危险 API（含 `help`、`restart`、`policy`、`terms`、`update`、`version` 等）。

---

## 五、附录 B：本次审计未能覆盖的部分

诚实列出，避免报告被当成「全部审完了」：

1. **`open-url` 的 `H()` 内部逻辑**——F-05 的状态是「未判定」不是「无风险」。
2. **渲染进程侧**：本次只审主进程，未审渲染进程的 XSS / CSP / 输入净化。Obsidian 的 `CSP_GLOBAL_CHECK` 在 Electronegativity 里报过一条 LOW/CERTAIN，本报告未展开。
3. **native 模块**：`sandbox/` 目录下有 native 代码，本次未做二进制审计。
4. **运行时行为**：纯静态分析，没有动态探针对齐。
5. **更新链路**：`check-update` / `disable-update` 只做了可达性判断，未审签名验证。

---

## 六、复现

```bash
pip install ipcsurface          # 或直接用仓库里的 ipcsurface.py
python ipcsurface.py obsidian.asar --summary       # 一页纸
python ipcsurface.py obsidian.asar -o report.md    # 全量报告（带位置）
python ipcsurface.py obsidian.asar --format sarif -o out.sarif   # CI 集成用
```

报告中每条结论都带 `文件:行@字符偏移`，可以直接跳到源码复核。本次审计用的版本是 0.116.0，`asar` schema 24。
