# 靶场

两个故意写坏的应用。源码是明的，答案就在手上，跑完可以自己核分。

REA 只认 `.asar`，所以先打包再分析。

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

期望结果：通道表里只剩 `ledger:clear` 一条字面通道。另外四处进不了表，但必须原样出现在「没看清的地方」，带表达式和行号。

这个靶子是为「动态生成」这条缺点建的。改之前，这四行会被静静吞掉，报告看着干净——干净才是危险的。

## obf-asar

故意做成被压过的样子：`_0x` 打头的变量、`eval`、`atob`、`fromCharCode` 拼字符串。

期望结果：三条以上混淆指纹被认出来，报告开头多一句「这包动过手脚」。

这里不要求它解出通道名。只要求它知道自己看不懂——认不出还装作认得出，才是坏的。

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
