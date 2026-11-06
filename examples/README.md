# 靶场

故意写坏的几个应用。源码是明的，答案就在手上，跑完可以自己核分。

REA 只认 `.asar`，所以先打包再分析。

## 改样本的时候，期望值要跟着改

期望值抄在 `scripts/selfcheck.py` 的 `TARGET_EXPECT` 里，自查会跑一遍核对。样本一改、期望值不跟着改，两种结果都会出事：数字对不上会红（好），或者有人图省事把期望值改成实际值（坏，等于把检查作废）。

所以改样本走三步：

1. 改源码，跑 `bash build.sh` 重新打包；
2. 跑一遍 `python ipcsurface.py examples/build/xxx-asar.asar`，看实际认出了几条；
3. **想清楚这个数为什么是它**，再改 `TARGET_EXPECT`。想不清楚就先别改——那说明还原逻辑出了你没料到的问题。

自查里还有一条比数字更硬的：`TARGET_EXPECT` 的键必须和 `examples/build/*.asar` 的集合完全一致。新加靶子忘了登记会红，删了靶子忘了删期望值也会红。

## static-asar

通道名全写死，其中一条是故意藏的 `ledger:__internal_sync`，配一串 token `e5f3a19b`。没有任何 sender 校验。

期望结果：

| 项 | 值 |
| --- | --- |
| 字面通道 | 5 条 |
| 暴露成员 | 5 个 |
| 两头配对 | 5 / 5 |
| 高危提示 | 无 sender 校验 |

五条通道和对应行号应该一条不差。

## dyn-asar

通道名是算出来的，四种拼法：

| 位置 | 写法 |
| --- | --- |
| `src/main.js:25` | `makeChannel(op)` |
| `src/main.js:28` | `'ledger:' + 'shadow'` |
| `src/main.js:29` | `` `ledger:${'tpl'}` `` |
| `src/preload.js:7` | `PREFIX + name` |

期望结果：通道表里能看到 `ledger:clear` 和 `ledger:shadow`。`'ledger:' + 'shadow'` 两头都是死字符串，工具会先折成一段；`makeChannel(op)`、模板串、`PREFIX + name` 这三处折不了，原样进「没看清的地方」，带表达式和行号。

这个靶子是为「动态生成」这条缺点建的。改之前，这四行会被静静吞掉，报告看着干净——干净才是危险的。

## obf-asar

故意做成被压过的样子：`_0x` 打头的变量、`eval`、`atob`、`fromCharCode` 拼字符串。

期望结果：三条以上混淆指纹被认出来，报告开头多一句「这包动过手脚」。

这里不要求它解出通道名。只要求它知道自己看不懂——认不出还装作认得出，才是坏的。

## bulk-asar

八百条通道。不是手写的，是 `python make-bulk.py` 生成的——手写八百行没意义，要的是数量。

期望结果：报告不散架。默认只列前三十条，其余折成一行，后面跟一句按前缀分组的统计。全文六十几行，不是八百行。

这一项专门盯「信息过载」：一个真实的商用应用，通道上百条是常态，能列完但没人看得完。

## native-asar

挂了一个 `src/native/ledger.node`。通道只有两条，重点不在这儿。

重点是报告得说出来：这包带着 native 模块，越界、泄漏、重复释放只可能在那些文件里，上面那张通道表跟它们没关系，两边得分开查。

如果报告不提这一句，读的人会以为查完 JS 就查完了。

## map-asar

包里带一份 sourcemap。`dist/bundle.min.js` 压得只剩 `a.ipcMain.handle(b.c,d)`，通道名一个都不在；但 `dist/bundle.min.js.map` 的 `sourcesContent` 里还留着原样的源码。

期望结果：通道表里出现 `vault:unlock` 和 `vault:__export_all`，位置写着 `dist/bundle.min.js.map → ../src/vault.ts:2`——一看就知道是从哪翻出来的。

这一项验的是「压过的包能不能翻回来」。能，但只在这个包里恰好带着 map 的时候能。

## obf2-asar

名字全提到数组里，代码里只按下标取：

```js
var _0x4a2f = ['vault:unlock', 'vault:lock', 'vault:__export_all', 'vault:status'];
ipcMain.handle(_0x4a2f[0], (event, payload) => ...);
```

期望结果：四条通道全部认出来，行号准确。

这是能还原的那一档。字符串池 + 数字下标，不需要执行代码，把下标换成字面量就行。解码函数、二次引用、控制流平坦化那些还原不了——那些得算值，算值就是执行。

## obf3-asar

中档：名字经过一个自解码函数才算得出来。

```js
function _d(s){ var out=''; for(...){ out += String.fromCharCode(s.charCodeAt(i) ^ 7); } return out; }
ipcMain.handle(_d('\x71\x66\x72\x6b\x73...'), (e, p) => ...);
```

期望结果：两条通道都还原（`vault:unlock`、`vault:lock`）。默认就会还原，不用加开关。

这一档原来是交给 Node 沙箱跑的（`tools/eval.js`），现在改成纯 Python：认函数体的形状，自己算，一行目标代码都不执行。所以它敢一直开着。想关就加 `--no-eval`。

## obf4-asar

套两层：名字先加一，再异或 7。`_d(_e('...'))`。

期望结果：加 `--eval` 之后一条通道还原成 `vault:unlock`。一轮只能剥一层，所以工具会来回跑几轮，直到不再变化。

这一项验的是「嵌套剥不剥得开」。剥得开，但只在这个参数是死字符串的前提下。

## obf5-asar

通道名单独放在 `channels.js`，主进程那边 import 进来用：

```js
const VAULT_UNLOCK_CHANNEL = 'vault:unlock';   // channels.js
ipcMain.handle(VAULT_UNLOCK_CHANNEL, ...);      // main.js
```

期望结果：两条通道都认出来。一个文件一个文件扫永远配不上这种，所以工具会先收一遍全包的字符串常量，第二遍扫的时候查表。

## 怎么跑

需要 Node、[REA](https://github.com/morluto/rea)、`@electron/asar`。

```bash
bash build.sh
```

脚本会依次打包两个靶子、跑 REA、再把证据压成报告，输出在 `build/`。想手动来：

```bash
cd examples

npx @electron/asar pack static-asar static-asar.asar
rea analyze-javascript-application static-asar.asar \
    --detail summary --evidence_output build/ev-static
ipcsurface build/ev-static build/static.md

npx @electron/asar pack dyn-asar dyn-asar.asar
rea analyze-javascript-application dyn-asar.asar \
    --detail summary --evidence_output build/ev-dyn
ipcsurface build/ev-dyn build/dyn.md
```

`build/` 不进版本库。`.asar` 也不进——它随时能打回来。
