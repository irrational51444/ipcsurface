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

~~CI 里起 `xvfb-run electron` 这一步还没落。~~ **已经在本机虚拟机里完整跑通了**
（2026-11-11，Ubuntu 26.10 虚拟机），对齐率复现 71%，跟之前 Windows 实测一致。
下面是可复现的 recipe，CI 那步照抄即可。

## 跑通的 recipe（虚拟机 / CI 通用）

环境：Ubuntu 26.10（VMware 虚拟机，NAT 网络）、node v24.19.0、npm 11。

1. 装依赖（apt 源用国内镜像更快）：
   ```
   sudo apt-get update && sudo apt-get install -y nodejs npm xvfb
   ```
2. 装 Electron + ws（github 被墙，Electron 二进制必须走国内镜像，否则 install.js 卡死）：
   ```
   ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/ \
     npm install --registry=https://registry.npmmirror.com
   ```
3. chrome-sandbox 设 setuid（否则 Electron 报 SUID sandbox 错误直接 abort）：
   ```
   sudo chown root:root node_modules/electron/dist/chrome-sandbox
   sudo chmod 4755 node_modules/electron/dist/chrome-sandbox
   ```
4. 跑探针：
   ```
   xvfb-run -a node run.js ../examples/static-asar 6 > probe.json
   ```
5. 比对齐率：`python scripts/probe_align.py probe.json examples/build/static-asar.asar`

结果（复现）：运行时 7 条、静态认得 5 条、对齐率 71%，漏的 2 条仍是
`IMPORT_SHARED_TEXTURE_*`（Electron 内置）和 `error`（Node 内置）——应用通道 5/5 全对齐。

## 怎么落 CI

把上面 1–4 步写进 ubuntu runner 的 job（步骤 2 的镜像环境变量照抄），
`probe_to_json.py` 转、`probe_align.py` 比，对齐率低于 71% 就红（基线从实测值起步）。
