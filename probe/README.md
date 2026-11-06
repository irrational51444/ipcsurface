# 运行时探针

静态分析只能猜。这一步让程序自己说。

## 它做什么

把一个 **没打包** 的 Electron 应用跑起来，打开主进程的调试口，问它三件事：

1. 注册过哪些 invoke 通道 —— 直接从 `ipcMain` 里读，不是猜的
2. 开了几扇窗口
3. 窗口真实的 `contextIsolation` / `nodeIntegration` / `sandbox`

第三件尤其值钱。静态分析只能说「源码里没写 sandbox」，运行时能告诉你「实际是 true」——因为默认值只有跑起来才算数。

## 装

```bash
npm install
```

要 Electron（跑目标用）和 ws（连调试口用）。

## 用

```bash
node run.js <未打包的应用目录> [等待秒数]
```

输出是 JSON，可以直接喂给主工具：

```bash
node run.js ../examples/static-asar 6 > probe.json
ipcsurface evidence --runtime probe.json -o surface.md
```

报告末尾会多一段「跑起来之后看见的」，静态没看见的通道会被标出来。

## 真的敲一遍（poke.js）

`run.js` 读的是登记表：程序说他注册了哪些通道。

`poke.js` 更进一步——挨个敲一遍。每条通道喂四种不合规的输入：`undefined`、空对象、十万个字符的字符串、`null`，记下它是抛错还是照收。

```bash
node poke.js ../examples/static-asar 6 > poke.json
ipcsurface evidence --poke poke.json -o surface.md
```

报告里会分出两栏：

- **照收的** —— 喂什么都不看，还返回了结果。这类最值得看：参数进来不检查就往下走，是这类通道最常见的问题。
- **抛错的** —— 可能人家本来就该拒。抛错不等于坏，得看它拒绝之前有没有干活。

静态分析永远看不出这一段。它只能告诉你「这扇门存在」，敲一下才知道门后面有没有人看门。

### 注意

**它会真的执行目标里的代码。** 只对自己的靶子、或者明确授权给你的程序用。

## 边界

- **只读。** 不写目标、不改目标、不往任何通道发消息。
- 只对**没打包的目录**有效。`.asar` 要先解开：`npx @electron/asar extract app.asar app/`。
- 要有图形界面。无头服务器上跑不起来。
- 通道注册要在启动阶段完成，不然等不到。等几秒由第二个参数定。
- 它拿到的是「注册过什么」，拿不到「谁有权调」。这两件事不一样。

## 为什么要它

`dyn-asar` 那种靶子，通道名是 `makeChannel(op)` 算出来的。静态分析到这儿就断了——只能把表达式原样贴出来说「这里有扇门，我不知道它通哪儿」。

跑起来，程序会自己把门上的号念一遍。
