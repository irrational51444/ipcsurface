# precise 引擎的已知边界（诚实清单）

precise（tree-sitter 精查层）是 P1-7 的产物。它比手写树强，但不是「0 ERROR = 全对」。

## 已经能做的

- 字符串字面量通道名 + 成员访问通道名（`IPC_EVENTS.X` 取属性名）；
- 同文件函数间接调用（`helper()` 一层层跟）；
- 跨文件 `require('./mod')` 调用（跟到被 require 模块的函数体）；
- 类方法跟随（`obj.method()` / `this.method()` 追到方法体）。

上面每一件都有用例锁着（`tests/test_precise.py`）。

## 已知边界（踩出来的，不是猜的）

1. **minified 代码里 tree-sitter 会「静默误解析」**：抖音 `EventCenter.js` 里
   `ipcMain.on(IPC_EVENTS.EVENTCENTER_MAIN_RECEIVE_EVENT, ...)` 这一段，tree-sitter
   报 0 ERROR，却把 `ipcMain.on(...)` 吞进一个巨大的 `this.???` 成员表达式里，
   字段遍历（`child_by_field_name('object')`）取出来的是 `this`，不是 `ipcMain`。
   —— 0 ERROR ≠ 解析正确，这是 tree-sitter 在压缩产物上的软肋，也是 precise 没检到
   `EVENTCENTER_*` / `REPORT_STAT` 那三条的直接原因。

2. **循环枚举没做**：抖音那 8 条字面量通道（`close` / `minimize` / `openFolder` …）
   是 `for (const name of [...]) ipcMain.on(name, ...)` 枚举出来的，precise 目前不展开
   循环，所以比手写扫描（它有 `enumerate_computed_names`）少认这 8 条。

3. **原生模块加壳读不出**：抖音 45 个 `.node` 开头不是 MZ，PE 导入表读不了，报告写
   「读不到」不写「没有」。

## 结论（一句实话）

precise 在「跨文件 / 类方法」上比手写树强，在「压缩产物 / 循环枚举」上还有和手写树
不一样的洞。两者不是谁碾压谁，是要**并列跑、拿差异当信号**——这正是 ADR 里「opt-in
而非替换」的理由。
