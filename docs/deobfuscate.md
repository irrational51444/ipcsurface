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

## 边界（诚实清单）

1. **`main/index.js` 还没解对**。它是多层包装 + 洗牌，解出来的字符串是残缺的
   （`Proces`、`Sessio`、`StateC` 这种错位片段）——参数映射还没理顺。桥接层已经能用，
   主进程层要继续调。
2. **只解字符串，不解控制流**。控制流平坦化、标识符重命名都还在，所以「哪条通道对应
   什么逻辑」还是看不清；但「有哪些通道名」这一层已经拿到了。
3. **需要 node**。零依赖的默认路径不受影响，这个脚本是额外的分析工具。

## 怎么用

```bash
python scripts/deobfuscate.py <混淆的 .js 或 .asar> [--json out.json]
```
