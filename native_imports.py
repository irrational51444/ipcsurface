"""native 模块的导入表也归进一个「面」（P1-5 收尾）。

抖音那种 45 个 .node 的危险不在 JS，在原生模块。这里把 asar 里的 .node/.dll
逐个解出来、读 PE 导入表、只记 DANGEROUS_IMPORTS 里那些（strcpy/system 之类）。

注意：抖音的 .node 是打包/加壳的（开头不是 MZ），导入表读不出来，返回空是
「读不到」不是「没有危险导入」——这两句别混。普通未加壳的 .node 才能读。
"""


def native_import_surface(files):
    """返回 {rel: [危险导入]}。"""
    import ipcsurface as _core  # 延迟导入，避免和本模块互相引用

    out = {}
    for rel in sorted(files.keys()):
        if not rel.endswith(('.node', '.dll')):
            continue
        data = files[rel]
        if data is None or not data.startswith(b'MZ'):
            continue
        try:
            imports = _core.parse_pe_bytes(data)
        except SystemExit:
            continue
        names = {fn.split('@')[0] for funcs in imports['libraries'].values() for fn in funcs}
        hits = sorted(names & set(_core.DANGEROUS_IMPORTS))
        if hits:
            out[rel] = hits
    return out
