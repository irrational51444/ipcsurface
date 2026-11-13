# 用 ipcsurface 审一个真实应用：Obsidian 1.11.7

这篇不是「工具很好用」的软文。是**真拿工具做一次审计**，把发现、误判、以及工具说不清的地方都写下来。

审计对象：`obsidian.asar`（28 MB，369 个文件，47 条通道）。

## 一、先看工具给了什么

```
python ipcsurface.py obsidian.asar --summary
```

```
通道 47 条
能碰到什么（共 116 条）
  direct 1 / name_confirmed 9 / chain 15 / ambiguous 41 / ast_only 50
没看清的（共 394 处）
  harvested-namespaced 394
```

硬结论 25 条，软结论 91 条。软的那 91 条按项目自己的规矩不该直接信，所以审计只从
25 条里挑。

## 二、验证三条硬结论

### 1. `vault-remove → unlinkSync`（工具标 direct）

源码（`main.js`，内偏移 191875）：

```js
ipcMain.on("vault-remove", (o, i) => {
  if (i && typeof i == "string") {
    for (let c in R) if (R[c].path === i) {
      if (Y[c]) { o.returnValue = false; return }   // vault 开着 → 拒绝
      o.returnValue = true, delete R[c], _(), ce(c), wt(c);
      return
    }
  }
  o.returnValue = false
});
```

**这里没有 `unlinkSync`。** 它在 `ce()` / `wt()` 里面。

**工具没错**，但**我对 `direct` 的理解错了**：我以为 `direct` 要求「字面就在函数体里」，
实际上它的定义是「hops ≤ 1」，一次函数调用后调到的也算。`ce(c)` 走到 `unlinkSync`
是 1 跳，所以归 `direct`。

**这是文档的锅**：`direct` 的说明应该写「一跳以内」，不是「自己直接调」。

### 2. `vault-move → renameSync`（工具标 name_confirmed）

源码（内偏移 192073）：

```js
ipcMain.on("vault-move", (o, i, c) => {
  if (i && typeof i == "string")
    for (let d in R) {
      let b = R[d];
      if (b.path === i) {
        if (Y[d]) { o.returnValue = "EVAULTOPEN"; return }
        try { m.renameSync(i, c) }              // ← c 完全没校验
        catch (k) { o.returnValue = k.toString(); return }
        o.returnValue = "", b.path = c, _();
        return
      }
    }
  o.returnValue = false
});
```

**这条工具报对了，但它没说清一个要紧的事**：

- `i`（源）校验了：必须是字符串，且必须等于已注册 vault 的路径
- **`c`（目标）一个校验都没有**：不检查类型、不检查范围、不检查是不是空

**后果**：能调这条通道的页面，可以让主进程把**任意一个已注册的 vault 目录** rename
到**任意路径**。

**边界也说清**：源路径必须是已注册的 vault，所以不是「任意文件任意移动」。但已注册
vault 里是用户的全部笔记。

**工具报的是「能碰到 renameSync」，报不了「参数校验缺在哪」。** 这一步必须人读源码。

### 3. `set-icon → rmSync`（工具标 name_confirmed）

源码（内偏移 194691）：

```js
ipcMain.on("set-icon", (o, i, c) => {
  C.icon && m.rmSync(F.join(v, C.icon), { force: true }),   // 删旧图标
  i && c ? m.writeFileSync(F.join(v, i), c) : i = null,     // 写新图标
  ...
});
```

**读起来没问题**：删的和写的都在 `v`（应用数据目录）下拼路径，`C.icon` 是上一次自己
存的值，不是外部直接给的。

**工具报的是「能碰到 rmSync + writeFileSync」，这条是真的，但风险等级被高估了**——
参数路径被 `F.join(v, ...)` 限住了。**这一层判断工具做不了，得人读。**

## 三、这一轮审计的实际收获

**工具做对的部分**：

- 47 条通道一条不漏（人工抽查过 5 条，全在）
- 25 条硬结论里，抽查 3 条，**全是真能碰到对应 API 的**
- 位置给到 `main.js:66@191875` 这种精度，直接跳过去就能看

**工具做不到的部分**：

- **说不了参数校验**。`vault-move` 那条最关键的事实——目标路径无校验——是我读源码
  才发现的，工具完全没提。
- **`direct` 的定义会让人误解**。它是一跳以内，不是字面可见。这件事工具的输出里看不
  出来，得查文档（而文档原来也没写清）。
- **软档 91 条基本没法用**。它们的「经过」列写着同名多义，实际读下来确实是压缩产物
  里同名函数混了。

## 四、给工具的两条改进（已记进 known-wrong）

1. **`direct` 的文档要写「hops ≤ 1」**，别写「自己直接调」——后者会让人以为必须字面
   在函数体里。
2. **报告里应该标「参数校验有没有被看到」**。现在只能标「能碰到 API」，标不了「能碰到
   之后有没有拦」。这条要动数据流分析，不是加个字段能完的。

## 五、结论

**这个工具能替人省掉「找门」那一步，省不掉「看锁」那一步。**

审计一个 28 MB 的 Electron 应用，工具跑了 45 秒给出 47 条通道和 116 条 sink 结论；
人工读那 25 条硬结论花了大约四十分钟，读出了上面这些。

**工具的价值不在「替人判断」，在「把该看的地方缩到 25 条」。** 这一点它做到了。
