# 运行时探针的对齐率（P1-8）

目标：让「静态分析到底漏了多少」有个可复算的指标，而不是「作者本机跑过」。

## 已经有的

- `probe/run.js` + `scripts/probe_preload.js`：在真 Electron 里起靶场，把运行时注册的
  通道名一行行吐出来；
- `scripts/probe_to_json.py`：把探针吐的 JSONL 转成 ipcsurface 能吃的 probe JSON；
- `scripts/probe_align.py`：拿 probe JSON 和静态 `analyse_asar` 比，算对齐率
  （运行时名字里静态认得的比例），并列出静态没认到的名字。

## 实测对齐率（examples/static-asar，2026-11-11）

运行时 7 条、静态 5 条、对齐 5 条，对齐率 71%。静态没认到的 2 条：

- `IMPORT_SHARED_TEXTURE_RELEASE_RENDERER_TO_MAIN` —— Electron 自带纹理共享通道，
  不是应用代码，静态本就不该有；
- `error` —— Node 进程的 `uncaughtException` 之类内置监听，不是 IPC 通道。

也就是说**应用自己注册的 5 条通道静态 5/5 全对齐**，那 2 条「漏」是平台内置，不是
静态的洞。所以对齐率要分「应用通道对齐」和「总对齐」两个口径报，别把内置算成漏。

## 还差的（诚实清单）

CI 里起 `xvfb-run electron` 这一步还没落。原因不是做不了，是 Electron 在 CI 里要
现下载几百兆、而且起窗口要 xvfb，这一串又慢又容易 flaky。对齐率脚本先立住了，
CI 那步留到「跑通一次本地 xvfb」之后再加，不然 CI 一红就是环境问题、不是回归。

## 怎么补

1. 在 CI 的 ubuntu runner 上装 electron + xvfb，`xvfb-run node probe/run.js <靶场目录> 6`；
2. `probe_to_json.py` 转、`probe_align.py` 比；
3. 对齐率低于一个从实测值起步的下限就红（同 P1-6 的路数：先测基线，再锁值）。
