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

## 边界

- **只读。** 不写目标、不改目标、不往任何通道发消息。
- 只对**没打包的目录**有效。`.asar` 要先解开：`npx @electron/asar extract app.asar app/`。
- 要有图形界面。无头服务器上跑不起来。
- 通道注册要在启动阶段完成，不然等不到。等几秒由第二个参数定。
- 它拿到的是「注册过什么」，拿不到「谁有权调」。这两件事不一样。

## 为什么要它

`dyn-asar` 那种靶子，通道名是 `makeChannel(op)` 算出来的。静态分析到这儿就断了——只能把表达式原样贴出来说「这里有扇门，我不知道它通哪儿」。

跑起来，程序会自己把门上的号念一遍。
