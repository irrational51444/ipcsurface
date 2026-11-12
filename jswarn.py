"""jswarn —— 预警引擎：证据强度 × 能力类别 → 预警级别。

三条硬规矩（少一条这套就变成「吓人的红点」）：
1. **预警必须引用已有的通道**：`entity` 字段指回那条 discovery，不能凭空产生。
2. **同一条 (entity, rule_id) 只发一次**：同一通道被同一规则刷屏，人就不看了。
3. **预警不得改变 tier**：预警是「提醒你看」，不是「替你定级」。

最要紧的一条在 `level_of()` 里：**借来档永远是 low，不管 sink 多高危**。
ambiguous 53%、ast_only 25%，把这两档染成 high 等于在视觉上说谎。
"""
import json
import os

# 危险 API → 能力类别。和 jslabels.RISK_CAPABILITY 的映射保持一致，
# 但这里只关心「严重程度」，所以合成为五类。
SINK_CATEGORY = {
    'exec': ('exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'),
    'file-write': ('writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
                   'createWriteStream', 'unlink', 'unlinkSync', 'rmSync', 'rename',
                   'renameSync', 'copyFile', 'copyFileSync', 'mkdir', 'mkdirSync',
                   'mkdtemp', 'mkdtempSync', 'rmdir', 'rmdirSync', 'truncate',
                   'truncateSync'),
    'file-read': ('readFile', 'readFileSync', 'createReadStream', 'readdir',
                  'readdirSync', 'lstat', 'stat', 'existsSync'),
    'network': ('fetch', 'request'),
    'eval': ('eval', 'Function'),
}

# 借来档：这两档在任何视图里都不许进 high
BORROWED_TIERS = frozenset(('ambiguous', 'ast_only'))
# 硬结论档：直接体可达 / 同名多义都确认过
HARD_TIERS = frozenset(('direct', 'name_confirmed'))

LEVEL_ORDER = ('high', 'medium', 'low', 'info')


def sink_category(api):
    """危险 API → 类别。不认识的返回 None（不认识就不预警，别猜）。"""
    for kind, names in SINK_CATEGORY.items():
        if api in names:
            return kind
    return None


def level_of(tier, category):
    """(证据强度, 能力类别) → 预警级别。

    这里的顺序是设计出来的，不是拍脑袋：
    - 借来档先判 low，**在判 sink 之前**——高危 sink 也不能把借来档顶上去；
    - 硬结论 + 执行/写文件/动态求值 = high（后果最重、证据最硬）；
    - 硬结论 + 读文件/网络 = medium；
    - 同文件链最多 medium。
    """
    if tier in BORROWED_TIERS:
        return 'low'
    if tier in HARD_TIERS:
        if category in ('exec', 'file-write', 'eval'):
            return 'high'
        return 'medium'
    if tier == 'chain':
        return 'medium' if category in ('file-read', 'network') else 'medium'
    # tier 认不出来：给 low，不借高档
    return 'low'


RATIONALE = {
    ('high', 'exec'): 'handler 直接可达命令执行 API，静态可见范围内未见对参数的校验',
    ('high', 'file-write'): 'handler 直接可达文件写入 API，静态可见范围内未见对路径参数的校验',
    ('high', 'eval'): 'handler 直接可达动态求值 API（eval / Function）',
    ('medium', 'file-read'): '可读文件；读本身不致命，但路径可控时能摸到敏感文件',
    ('medium', 'network'): '可发起网络请求；目标地址来自参数时可能被利用',
    ('low', 'exec'): '借来档，但 sink 属于命令执行——**需人工核**，不要当结论',
    ('low', 'file-write'): '借来档，但 sink 属于文件写入——**需人工核**，不要当结论',
    ('low', 'eval'): '借来档，但 sink 属于动态求值——**需人工核**，不要当结论',
}


def rationale_for(level, category, tier):
    text = RATIONALE.get((level, category))
    if text:
        return text
    if level == 'low':
        return f'证据强度 {tier}，属于「看过但不确定」的档位，需人工核'
    return f'能力类别 {category}，证据强度 {tier}'


def build_warnings(facts):
    """算出这份扫描该发哪些预警。返回 list[dict]，已按 (entity, rule_id) 去重。

    每条预警的形状：
        {'entity': 通道名, 'rule_id': 'sink-exec', 'level': 'high',
         'tier': 'direct', 'sinks': ['exec'], 'rationale': '...'}
    """
    tiers = facts.get('channel_sink_tiers') or {}
    sinks_by_channel = facts.get('channel_sinks_ast') or facts.get('channel_sinks') or {}
    out = []
    seen = set()
    for channel in sorted(tiers):
        api_tiers = tiers.get(channel) or {}
        # 按类别聚合：一个通道 + 一个类别只发一条（规矩 2）
        bucket = {}
        for api, tier in api_tiers.items():
            category = sink_category(api)
            if category is None:
                continue
            slot = bucket.setdefault(category, {'tier': tier, 'sinks': []})
            slot['sinks'].append(api)
            # 同一类别里取最强的档当代表
            if _rank(tier) < _rank(slot['tier']):
                slot['tier'] = tier
        for category, slot in bucket.items():
            rule_id = 'sink-' + category
            key = (channel, rule_id)
            if key in seen:
                continue
            seen.add(key)
            level = level_of(slot['tier'], category)
            out.append({
                'entity': channel,
                'rule_id': rule_id,
                'level': level,
                'tier': slot['tier'],
                'sinks': sorted(set(slot['sinks'])),
                'rationale': rationale_for(level, category, slot['tier']),
            })
    out.sort(key=lambda w: (LEVEL_ORDER.index(w['level']), w['entity']))
    return out


_ORDER = ('direct', 'name_confirmed', 'chain', 'ambiguous', 'ast_only')


def _rank(tier):
    """档位强弱排序，越小越硬。不认识的排最后。"""
    try:
        return _ORDER.index(tier)
    except ValueError:
        return len(_ORDER)


def load_rules(path=None):
    """从 JSON 读规则覆盖。不给 path 就返回内置的那套。

    预留口子：以后要做「规则文件可配」，走这里，不改代码。
    """
    if not path or not os.path.exists(path):
        return {'levels': 'builtin', 'counts': len(RATIONALE)}
    with open(path, encoding='utf-8') as fh:
        return json.load(fh)
