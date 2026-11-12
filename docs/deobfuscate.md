# 解混淆：把混淆里藏着的字符串捞出来

bilibili 的 `main/index.js` 用了 obfuscator.io 最高档混淆——连 `ipcMain` 这个词都被换成
`_0x...`，字符串全编码进一个数组，用 base64 变体 + RC4 解密。静态扫描按名字匹配，
天然扫不到，最后只认出 1 条（还是第三方库 electron-store 的）。

`scripts/deobfuscate.py` 做第一步：**还原字符串数组**。

## 识别四件套

1. **数组函数**：函数体里有一个大字符串数组（≥50 个 `'\x..'`），且自覆盖
   （`fn = function(){ return arr }`）。
2. **解码函数**：函数体里有 `0x100` 的 RC4 S 盒 + base64 解码表 + `decodeURIComponent`。
3. **洗牌 IIFE**：文件头部的 `(function(e,f){...}(数组函数, 校验值))`，靠 `push(shift())` 打乱顺序。
4. **调用点**：`别名(0xIDX, '\x..KEY..')`，别名可能是解码函数本身，也可能是多层包装函数。

## 做法

从调用点出发，把它们碰到的函数定义全递归捞出来（混淆的包装层数不定），拼成一个
Node 脚本跑：数组函数 → 其它函数 → 洗牌 → 逐个 eval 调用点 → 去重。

两个关键坑：

- **别名不能直接调**。解码函数会自覆盖，`var ax = d;` 拿到的 `ax` 永远指着「旧函数」，
  而旧函数只返回新函数、不返回字符串。所以调用点里的别名要统一改回解码函数名。
- **调用点别丢函数名**。只抓 `(0xIDX, 'KEY')` 这半截，eval 出来是 key 本身，不是解码结果。

需要 `node`（跑解码逻辑）。没装 node 就报「没解」，不猜。

## 实测（bilibili 1.17.2，2026-11-12）

`main/assets/bili-bridge.js`（桥接层，32 KB）：

```
解出 62 个字符串，其中 49 个像通道名
  app/getAppInfo  app/isDev  app/isDevMode  app/installVersion  app/buildCode
  app/getTheme  app/launchAction  app/mainProcessReady
  auth/getAppInfo  auth/getMediaAccessStatus
  system/isMac  system/isWin  system/isLinux  system/isNetOnLine
  system/getAppPath  system/getFontsInfo  system/getAbTestInfo  system/checkIsGrayHit
  config/isMainWindowReady  config/getSystemFont  config/getIsDisableGpu  ...
  window/isPined  window/isFocused  window/isVisible  window/isMinimized  window/isMaximized
  window/isFullScreen  window/isMainWindowMini  window/isMiniPlayerMode
  window/isLiveRoomWindowVisible  window/isBiliPetVisible
```

**从 1 条到 49 条**——这些就是 bilibili 渲染进程能调的通道名，藏在混淆的字符串数组里。

## 这 49 条的证据强度（别因为数字好看就升档）

| 项 | 状态 |
| --- | --- |
| 来源 | 桥接层 `bili-bridge.js` 静态还原 |
| 证据强度 | **还原档**（字符串数组解出来的，不是逐字写死的） |
| 主进程注册点 | **未确证**——没在 `main/index.js` 里找到对应的 `ipcMain.handle('app/getAppInfo', ...)` |
| sink | **未追**——这些通道背后碰了什么危险 API，没看 |

所以正确的读法是：**「渲染进程能调这 49 个名字」，不等于「主进程注册了这 49 条、也不等于它们危险」**。

## 已知明文反查：49 条在 main/index.js 里 0 命中 —— 这是「加密壳」案例

拿这 49 条当探针，去 `main/index.js` 的解码输出里精确匹配：

```
main/index.js 解出 141 个字符串
精确命中已知通道名：1 条（'search'，通用词，不算）
部分包含 app/ system/ window/ config/ auth/：0 条
明文/编码明文里搜 'getAppInfo' 'isWin' 'ipcMain' 'handle'：全部 0 次
```

**匹配失败本身就是情报**。继续查，发现：

- `main/.biliapp` 是 **3.1 MB 的 hex 文本**，解 hex 后是 1.58 MB 二进制，不是 gzip/zlib，
  是一段**加密数据**（AES 之类）。
- `main/index.js` 里搜 `biliapp`、`decrypt`、`aes`、`crypto`：全部 0 次（连读它的逻辑也混淆了）。

结论（这条比「读不到」专业得多）：

> **bilibili 的主进程是「加密壳 + 混淆」两层，静态审计止于桥接层。**
> 主进程真正的注册点在 `.biliapp` 解密后的代码里，要拿到它只有动态手段。

`main/index.js` 只是解密壳，负责「解开 .biliapp 再加载」。所以「静态反查失败」不是解码写错了，
是**那层代码根本不在 JS 文件里**。

## 抽查：5 条通道名的人工确认

解码结果有可能是「看似合理、实际是 key 本身」的假阳性，所以要抽检上下文：

| 通道名 | 索引 | key | 上下文证据 |
| --- | --- | --- | --- |
| `app/getAppInfo` | 0x1d5 | `3LMy` | 出现在 `var ak=[aA(0x1d5,'3LMy'), aA(0x1b5,'3LMy'), '\x61\x70\x70\x2f\x69\x73\x52...']` —— 同一个数组里混着**明文** `app/isR...`，是通道名清单 |
| `system/isWin` | 0x1df | `#T($` | 同形态数组：`aA(0x1ee,'G4E$'), aA(0x1df,'#T($'), aA(0x1a0,'!bSE'), aA(0x1cd,'gHoR')` |
| `biliBridgePc` | 0x1e4 | `cS[X` | `aj['contextBridge'][aA(0x18b,'I&&1')](aA(0x1e4,'cS[X'), {callNative: al, ...})`，即 `contextBridge.exposeInMainWorld('biliBridgePc', {...})` |
| `exposeInMainWorld` | 0x1f7 | `MeUw` | `aI(0x1f7,'MeUw')('reportObserver', ...)` 另一个暴露点 |
| `app/isDev` | — | — | 和 `app/getAppInfo` 同数组，形态一致 |

**抽检结论**：解出来的不是 key 本身——key 是 4 个随机字符（`3LMy`、`#T($`），
解出来的是 `app/getAppInfo` 这种带 `/` 的语义字符串，且和明文 `app/isR...` 出现在同一个数组里。
两条独立的线索对上，可信。

## 边界（诚实清单）

1. **桥接层能解，主进程层解不了**。主进程代码加密在 `.biliapp` 里，静态到此为止。
   下一步要么做 `.biliapp` 解密（需要找到密钥和算法），要么走运行时（探针/劫持）。
2. **main/index.js 解出来的残缺字符串不是通道名**。`Proces`、`Sessio`、`StateC` 这些
   是「包装函数索引映射」的中间产物（我用第一个参数当索引，而包装函数用的是第三个参数
   减偏移），且这个文件本来就不含通道名——不要拿它当「解出了半截通道名」。
3. **只解字符串，不解控制流**。标识符重命名、控制流平坦化都还在。
4. **需要 node**。零依赖的默认路径不受影响。

## 怎么用

```bash
python scripts/deobfuscate.py <混淆的 .js 或 .asar> [--json out.json]
```
