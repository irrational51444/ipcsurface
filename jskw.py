"""JS 保留字：一处定义，各层按需取子集。

同一个 bug 在三层各犯过一次（词法层不当调用边、语法树层、函数定义层把
`if (x) {}` 当成方法简写）。根因不是某个层写错，是**三层各有一份自己的
关键字清单**，改一层漏两层。

现在只有这一份 `JS_RESERVED`。各层用 `subset(...)` 取自己需要的那部分：
名字写错直接抛错，不会静默漏掉。
"""

JS_RESERVED = frozenset({
    # 控制流
    'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default',
    'break', 'continue', 'return', 'throw', 'try', 'catch', 'finally',
    # 声明与作用域
    'var', 'let', 'const', 'function', 'class', 'extends', 'super', 'this',
    'new', 'delete', 'typeof', 'instanceof', 'in', 'of', 'void', 'with',
    'yield', 'await', 'async', 'static', 'get', 'set',
    # 模块
    'import', 'export', 'from', 'as',
    # 其他
    'debugger', 'null', 'true', 'false', 'undefined',
})


def subset(*names):
    """取保留字的一个子集；不在 `JS_RESERVED` 里的名字直接报错。

    报错而不是静默忽略：拼错一个关键字，等于那一层悄悄少排一个词，
    而这正是这个 bug 三次复发的方式。
    """
    unknown = set(names) - JS_RESERVED
    if unknown:
        raise ValueError('不是 JS 保留字：%s' % '、'.join(sorted(unknown)))
    return frozenset(names)
