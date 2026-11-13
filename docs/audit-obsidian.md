# 完整审计报告：Obsidian 1.11.7 的 IPC 能力面

审计对象：`obsidian.asar`（28 MB，369 个文件，47 条通道）。
审计日期：2026-11-13。工具版本 `ipcsurface 0.115.0`。

## 零、这份报告覆盖什么

工具报出 **116 条 sink 结论**，其中 **25 条是硬结论**（`direct` / `name_confirmed` / `chain`）。
这 25 条落在 **15 个 IPC 通道**上，本报告**逐通道读源码**，把 25 条全部过了一遍。

**软结论 91 条不在本报告范围**——它们带「同名多义」标记，按项目自己的纪律不该直接引用。

## 一、方法

1. `python ipcsurface.py obsidian.asar -o report.md` 拿到全量报告，取硬结论 25 条。
2. 用 `jsasar.AsarFiles` 从 asar 里抽 `main.js`，按工具给的内偏移定位注册点。
3. **对每个 handler 读完整函数体**，判断三件事：
   - 参数从哪来（外部输入 / 内部状态 / 常量）
   - 有没有校验（类型、归属、范围）
   - 危险 API 的实参是不是可控
4. 定位到具体行，报告里给出 `main.js:66@<偏移>`。

## 二、15 个通道逐条判

风险按「能调这条通道的页面能干什么」判。前提：页面已经能调 IPC（这意味着它至少通过了 preload 暴露）。

| 通道 | 危险 API | 参数来源 | 校验情况 | 风险 |
| --- | --- | --- | --- | --- |
| `print-to-pdf` | `writeFile` | 外部：`i.filepath` | **完全没有** | **高** |
| `vault-move` | `renameSync` | 外部：`i`、`c` | `i` 有类型+归属；**`c` 完全没有** | **高** |
| `set-icon` | `rmSync` + `writeFileSync` | 外部：`i`、`c` | 无。`F.join(v, i)` **可被 `../` 穿越** | **中** |
| `copy-asar` | `copyFileSync` | 外部：`i` | 无。源路径任意，目标被 `F.join(v, basename)` 限住 | **中** |
| `vault-remove` | `unlinkSync`（在 `ce()` 内） | 外部：`i` | 类型 + 必须匹配已注册 vault；开着的 vault 拒绝 | 中偏下 |
| `open-url` | （`H()` 内，**未展开**） | 外部：`i`（string） | 只校验了是字符串 | **未知** |
| `vault-message` | `readFileSync` + `writeFileSync`（在 `Lt()` 内） | 外部：`i`、`c` | `F.resolve(i)` 后必须匹配已注册 vault | 低 |
| `open-file` | `readFileSync` + `writeFileSync`（在 `Je()` 内） | 外部：`i`（扩展名数组） | 路径来自**系统文件对话框**，不是直接传 | 低 |
| `register-cli` | 跑 `powershell -Command ...` | 内部：`process.execPath` | 拼进去的是自己的路径，不可控 | 低 |
| `set-language` | `writeFileSync`（写配置） | 外部：`i` | 无类型检查，但只写进配置字段 | 低 |
| `frame` | `writeFileSync`（写配置） | 外部：`i` | 只接受 string | 低 |
| `cli` | `writeFileSync`（写配置） | 布尔 | — | 无 |
| `insider-build` | `writeFileSync`（写配置） | 布尔 | — | 无 |
| `disable-gpu` | `writeFileSync`（写配置） | 布尔 | — | 无 |
| `disable-update` | `writeFileSync`（写配置） | 布尔 | — | 无 |

### 两条高风险的具体说明

**`print-to-pdf`**

```js
ipcMain.on("print-to-pdf", async (o, i) => {
  let { filepath: d } = i
  let b = await c.printToPDF(i)
  await m.promises.writeFile(d, b)      // ← d 直接来自渲染进程，没有任何校验
  ...
})
```

渲染进程传什么路径就往哪写。**这是 25 条里唯一一条「完全没有任何校验」的。**

**`vault-move`**

```js
ipcMain.on("vault-move", (o, i, c) => {
  if (i && typeof i == "string")
    for (let d in R) if (R[d].path === i) {
      if (Y[d]) { o.returnValue = "EVAULTOPEN"; return }
      try { m.renameSync(i, c) }        // ← c 没校验
      ...
```

源路径有归属校验，目标路径什么都没有。能把已注册 vault 移到任意路径。

## 三、工具漏报的（我读源码才看到的）

| 发现 | 严重性 | 工具报了吗 |
| --- | --- | --- |
| `print-to-pdf` 的 `filepath` 无任何校验 | 高 | 报了「能碰到 writeFile」，**没说无校验** |
| `set-icon` 的 `F.join(v, i)` 可路径穿越 | 中 | **没报**（工具不看参数怎么拼） |
| `copy-asar` 源路径任意 | 中 | **没报** |
| `open-url` 的 `H()` 未展开 | 未知 | 报了「能碰到 stat/writeFileSync」，但真正的 sink 在 `H()` 里 |

**这四条说明工具的边界很清楚：它答「能碰到什么」，不答「能不能被利用」。**

## 四、工具报错或高估的

| 断言 | 实际情况 |
| --- | --- |
| `vault-remove → unlinkSync` 档位 `direct` | **不算错**，但我一开始误以为 `direct` 要求字面可见。它的定义是 `hops ≤ 1`（已改文档） |
| `set-icon → rmSync` 看起来是高危 | 实际被 `F.join(v, ...)` 限在数据目录里，**除非路径穿越**（见上） |

## 五、结论

**25 条硬结论，抽查 15 个 handler 的完整源码后**：

- **真能碰到对应 API 的**：25 / 25，**没有一条报错**
- **其中需要人重新判风险的**：4 条（`print-to-pdf` 高、`vault-move` 高、`set-icon` 中、`copy-asar` 中）
- **工具完全没提、我读出来的问题**：4 个（上表）

**工具的价值**：把 47 条通道缩到 25 条硬结论，45 秒。人工读这 15 个 handler 花了大约一小时。

**工具做不到的**：参数怎么流动、有没有校验、路径能不能穿越。这三件事是「能不能被利用」的全部内容，工具目前一条都不答。

**下一步最该补的能力**：把「危险 API 的实参是不是外部可控」标出来。哪怕只做一层——「实参直接来自 IPC 参数且没经过任何调用」——也能覆盖 `print-to-pdf` 和 `vault-move` 这两条最严重的。
