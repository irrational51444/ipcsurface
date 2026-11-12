"""报告层：把事实摊成人能读的 Markdown，以及基线比对、可信度分层。

从 ipcsurface.py 切出来的第三刀。前两次都失败：一次按行号硬切把常量区切坏，
一次只搬函数不搬常量依赖的辅助函数。这次按「谁用谁」求传递闭包，
闭包里整段搬走，搬完先 import，过不了就不落盘。

约束：
- 这里**不许 import ipcsurface**（会循环引用）；版本号由调用方传进 stamp(version)；
- 报告只摆证据、不下结论。
"""
import hashlib
import json
import os
import re
import struct
from collections import defaultdict

import jslabels


from jslabels import HARVEST_GRADES, danger_kind_of
HIGH_RISK_HINTS = ('__', 'internal', 'debug', 'admin')

# 由主模块注入覆盖（和 VERSION 一样）；这里给个和源码一致的默认值，
# 免得指纹里的 schema 又漂回旧值。
SCHEMA = 'ipcsurface/asar/21'


def stamp(version=None):
    """报告里带生成时间和版本——审出来的东西要能对上号。

    version 由调用方传进来：这一层不许 import 主模块，否则循环。
    """
    return jslabels.stamp(version or VERSION)


def audit_asar(facts):
    """粗扫也有可疑项。不然挂在 CI 上的 --fail-on 在这条路上等于没用。"""
    findings = []
    for name, where, level in facts['obfuscation']:
        if level == 'strong':
            findings.append(('high', f'强混淆指纹：{name}', where))
    for name, where in facts['handlers']:
        low = name.lower()
        if any(hint in low for hint in HIGH_RISK_HINTS):
            findings.append(('medium', f'通道名带隐藏意味：{name}', where))
    return findings


STATIC_SOURCES = ('literal', 'literal-resolved', 'enumerated', 'computed', 'harvested')


ALL_SOURCES = STATIC_SOURCES + ('runtime',)


def _build_independence():
    table = {}
    for i, left in enumerate(ALL_SOURCES):
        for right in ALL_SOURCES[i + 1:]:
            pair = '|'.join(sorted((left, right)))
            # 同一个包的两条静态读法共享同一份源码和同一张常量表，不算独立见证；
            # 运行时是另一条路，和任一静态来源都独立。
            table[pair] = (left == 'runtime') != (right == 'runtime')
    return table


INDEPENDENCE_TABLE = _build_independence()


def independent(left, right):
    return INDEPENDENCE_TABLE['|'.join(sorted((left, right)))]


ACTION_BY_SOURCE = {
    'literal': 'cite',
    'literal-resolved': 'spot_check_source',
    'enumerated': 'spot_check_source',
    'runtime': 'trust_after_setup',
    'computed': 'read_code',
    'harvested': 'triage',
}


ACTION_STRICTNESS = ['cite', 'spot_check_source', 'trust_after_setup', 'read_code', 'triage']


SOURCE_STRENGTH = {
    'literal': 1.0,
    'literal-resolved': 0.9,
    'runtime': 0.8,
    'enumerated': 0.9,
    'computed': 0.3,
    'harvested': 0.2,
}


ENUM_STRENGTH_PROVEN = 0.9


ENUM_STRENGTH_OPEN = 0.6


# sink 路径强度档，从高可信到低可信。顺序就是校准脚本单调性断言的依据。
# 校准实测（docs/calibration.md）：direct/name_confirmed/chain 三档 100%，
# ambiguous 53%，ast_only 25%——这条梯度真的能把「更可能错的 API」分出来。
SINK_TIER_ORDER = ['direct', 'name_confirmed', 'chain', 'ambiguous', 'ast_only']


def sink_tier(facts, channel, api):
    """一条危险 API 的「来路可信度」档，从高到低。

    - direct          处理函数自己直接调（hops≤1），且没经过同名多义
    - name_confirmed  语法树和名字级双口径都报，但路径没记录（别名/成员调用）
    - chain           同文件内经过一层函数链（hops>1），无同名多义
    - ambiguous       经过同名多义链（via 带「同名多义」，或通道在 ambiguous 名单）
    - ast_only        只有语法树口径连上，名字级没连上（最可疑）
    """
    paths = facts.get('channel_sink_paths') or {}
    sinks = facts.get('channel_sinks') or {}
    ambiguous = set(facts.get('channel_sinks_ambiguous') or [])
    path = paths.get(channel, {}).get(api)
    in_names = api in (sinks.get(channel) or [])
    if path is None:
        return 'name_confirmed' if in_names else 'ast_only'
    via = path.get('via', '')
    if '同名多义' in via or channel in ambiguous:
        return 'ambiguous'
    return 'direct' if path.get('hops', 9) <= 1 else 'chain'


def channel_profiles(facts, evidence):
    """每条通道一份档案：能碰什么、什么能力、来路档、代码位置、证据来源。

    报告里以前是「通道 → API」和「通道 → 来源」分开列，读的人要自己拼。
    这里合成一份：一条通道一行，能力标签、代码位置、证据来源都在。
    """
    sinks = facts.get('channel_sinks_ast') or facts.get('channel_sinks') or {}
    tiers = facts.get('channel_sink_tiers') or {}
    profiles = {}
    for name, apis in sinks.items():
        if not apis:
            continue
        ev = evidence.get(name) or {}
        profiles[name] = {
            'sinks': sorted(apis),
            'risk_labels': jslabels.risk_labels(apis),
            'sink_tiers': tiers.get(name) or {},
            'where': ev.get('where'),
            'sources': ev.get('sources') or [],
        }
    return profiles


def channel_sources(facts, probe=None):
    """每条通道名各自是被谁看见的。

    一层给整份报告定强度，还不够——同一个包里，有的名字是写死的，
    有的只在运行时见过，混在一起就会互相借光。这条函数按名字拆开记来源。
    """
    seen = {}
    actual = {}      # (名字, 来源) → 这一处实际的强度：穷举那条按检查结果分档

    def add(name, source, strength, where=None):
        item = seen.setdefault(name, {'sources': [], 'strength': 0.0,
                                      'where': None, 'where_all': []})
        if source not in item['sources']:
            item['sources'].append(source)
        if strength > item['strength']:
            item['strength'] = strength
        key = (name, source)
        if strength > actual.get(key, -1.0):
            actual[key] = strength
        if where:
            if not item['where']:
                item['where'] = where
            if where not in item['where_all']:
                item['where_all'].append(where)

    enum_proof = {}   # (名字, 位置) → {'checked': [...], 'failed': [...], 'basis': ...}
    enumerated_sites = set()
    for name, where, basis, passed, failed in (facts.get('enumerated') or ()):
        enumerated_sites.add((name, where))
        enum_proof[(name, where)] = {'basis': basis,
                                     'checked': list(passed),
                                     'failed': list(failed)}
    for name, where in facts['handlers'] + facts['invokes'] + facts['exposes']:
        if name in facts.get('resolved', ()):
            # 名字是靠还原推出来的，不是逐字写在那儿，强度低一档
            add(name, 'literal-resolved', 0.9, where)
        elif (name, where) in enumerated_sites:
            # 穷举出来的：检查全过才算「证明到位」，0.9，和靠还原的同档；
            # 有一条没过就降到 0.6——名字照给，但别拿它当准的用。
            # 按「这一处」判，不按名字判：同一个名字在别处逐字写着，就按写死的算。
            failed = enum_proof[(name, where)]['failed']
            add(name, 'enumerated', ENUM_STRENGTH_PROVEN if not failed
                else ENUM_STRENGTH_OPEN, where)
        else:
            add(name, 'literal', 1.0, where)
    if probe and not probe.get('error'):
        for name in probe.get('handlers') or []:
            add(name, 'runtime', 0.8)
        for name in probe.get('listeners') or []:
            add(name, 'runtime', 0.8)
        # 探针有时会给位置（窗口/文件），有就记，没有就留空
        for name, where in (probe.get('sites') or {}).items():
            item = seen.setdefault(name, {'sources': [], 'strength': 0.0,
                                          'where': None, 'runtime_where': None})
            item['runtime_where'] = where
    for what, where in facts['dynamic']:
        add(what, 'computed', 0.3, where)
    grades = facts.get('harvest_grades') or {}
    for name, value in (facts.get('harvested') or {}).items():
        where = value[0] if isinstance(value, tuple) and value else None
        add(name, 'harvested', 0.2, where)
        if name in grades:
            seen[name]['harvest_grade'] = grades[name]
    caps = facts.get('capability') or {}
    for name, info in caps.items():
        if name in seen:
            seen[name]['capability'] = info

    for name, item in seen.items():
        item['sources'] = sorted(item['sources'])
        # 一个名字可能有多个来源，动作按最严格的那个给，别让人猜听谁的
        actions = [ACTION_BY_SOURCE[s] for s in item['sources'] if s in ACTION_BY_SOURCE]
        item['actions'] = sorted(set(actions), key=ACTION_STRICTNESS.index)
        item['primary_action'] = max(actions, key=ACTION_STRICTNESS.index) if actions else 'review'
        # 对上要分种类：按判定表数一数，有没有一对是互不依赖的
        srcs = item['sources']
        pairs = [(a, b) for i, a in enumerate(srcs) for b in srcs[i + 1:]]
        has_independent = any(independent(a, b) for a, b in pairs)
        static_sources = {'literal', 'literal-resolved', 'enumerated',
                          'computed', 'harvested'} & set(srcs)
        if has_independent:
            item['corroboration'] = 'static_runtime'
        elif len(static_sources) >= 2:
            item['corroboration'] = 'static_static'
        else:
            item['corroboration'] = 'none'
        item['corroborated'] = item['corroboration'] == 'static_runtime'
        # 「对上」只说明两条路互不依赖，不说明两条路都硬。
        # 把每一侧的硬度也带上，免得一个布尔把差异盖掉。
        # 实际强度按这一处算：穷举那条同是 enumerated 来源，可能是 0.9 也可能是 0.6。
        item['strength_by_source'] = {
            s: actual.get((name, s), SOURCE_STRENGTH.get(s, 0.0)) for s in item['sources']}
        # 最弱可能不止一个，用列表；字段名要是单数，读的人会以为只有一个
        lowest = min(item['strength_by_source'].values())
        item['weakest_sources'] = sorted(s for s, v in item['strength_by_source'].items()
                                         if v == lowest)
        item['weakest_strength'] = lowest
        item['independent_pairs'] = ['%s+%s' % (a, b) for a, b in pairs if independent(a, b)]
        item['refutes_if'] = refutes_if(item['sources'])
        proofs = [enum_proof[key] for key in enum_proof if key[0] == name]
        if proofs:
            item['enum_proof'] = proofs[0] if len(proofs) == 1 else proofs
        if item['corroboration'] == 'static_runtime':
            level, basis = corroboration_strength(item.get('where'),
                                                  item.get('runtime_where'))
            item['corroboration_level'] = level
            item['corroboration_basis'] = basis
    return seen


def corroboration_strength(static_where, runtime_where):
    """两条证据「交叉得有多实」。

    同文件相邻行和「一个在主进程、一个在渲染进程包里」显然不是一回事。
    但如果运行时那侧没给位置，就老实说 unknown——不拿「都看见了」冒充强度。
    """
    if not static_where:
        return 'unknown', '静态那一侧没有位置'
    if not runtime_where:
        return 'unknown', '运行时那侧没给位置，分不出独立还是相邻'

    def split(where):
        text = str(where)
        if ':' in text:
            path, _, line = text.rpartition(':')
            try:
                return path, int(line)
            except ValueError:
                return path, None
        return text, None

    s_path, s_line = split(static_where)
    r_path, r_line = split(runtime_where)
    if s_path == r_path:
        if s_line is not None and r_line is not None:
            gap = abs(s_line - r_line)
            if gap == 0:
                # 同一行：基本就是同一处代码的两种视角，独立性最低
                return 'weak-same-line', f'同一个文件、同一行（{s_path}:{s_line}）'
            if gap <= 5:
                # 相邻但不同行：可能是同一个调用点，也可能只是碰巧挨着。
                # 静态没法分辨这个，所以档位名字只说「相邻」，不说「同源」。
                return 'weak-near-line', (
                    f'同一个文件、相隔 {gap} 行（{s_path}:{s_line} / {r_line}）；'
                    '分不清是同一个调用点还是只是相邻')
        return 'medium', f'同一个文件的不同位置（{s_path}）'
    return 'strong', f'两个不同文件：{s_path} / {r_path}'


REFUTES = {
    'literal': '在源码里搜不到这个字符串（或它只是注释/文档里的示例）',
    'literal-resolved': '常量表里查不到这个名字，或那张表在更早的地方被整个覆盖',
    'enumerated': '那个循环里有人改过变量（或取值集合不是字面量数组），'
                  '拼出来的名字就不止这几个',
    'runtime': '程序跑起来后，运行时不注册这个名字',
    'computed': '调用点的参数在运行时算出来是另一个值',
    'harvested': '这个字符串不是通道名，只是长得像',
}


def refutes_if(sources):
    """哪几种观察能推翻这条结论。只给能推翻的，不给能「证实」的。"""
    out = []
    for source in sources:
        text = REFUTES.get(source)
        if text and text not in out:
            out.append(text)
    return out


def sample_sites(facts, limit=2, only_resolved=False, only_enumerated=False):
    """抽一两条能自己核对的样本：名字 + file:line。

    有样本才叫「你能查」，没样本就只能「你信我」。
    """
    resolved = set(facts.get('resolved') or ())
    enumerated = {item[0] for item in (facts.get('enumerated') or ())}
    candidates = []
    seen = set()
    for name, where in (facts['handlers'] + facts['invokes'] + facts['exposes']):
        if name in seen:          # 同一个名字可能同时出现在 handler 和 invoke 里
            continue
        if only_resolved and name not in resolved:
            continue
        if only_enumerated and name not in enumerated:
            continue
        if not only_resolved and not only_enumerated and (name in resolved
                                                         or name in enumerated):
            continue
        seen.add(name)
        candidates.append({'name': name, 'where': where})
    # 按名字的 sha1 排，谁的机器上看都是同两条——样本能互相复核才对得上
    candidates.sort(key=lambda item: hashlib.sha1(
        item['name'].encode('utf-8')).hexdigest())
    return candidates[:limit]


def confidence_levels(facts, probe=None, poke=None):
    """这份报告里每一样东西，各自能证明到什么程度。

    人看容易把不同强度的话当成一样重；机器读更容易——它只会被字段名骗。
    所以这一层既给人看，也直接进 JSON：强度用数字，未知用 null，不用 0 顶替。
    """
    literal = len(facts['handlers']) + len(facts['invokes']) + len(facts['exposes'])
    resolved_names = set(facts.get('resolved') or ())
    enumerated_sites = {(item[0], item[1]) for item in (facts.get('enumerated') or ())}
    occurrences = facts['handlers'] + facts['invokes'] + facts['exposes']
    literal_resolved = sum(1 for name, _where in occurrences if name in resolved_names)
    enumerated_count = sum(
        1 for name, where in occurrences
        if name not in resolved_names and (name, where) in enumerated_sites)
    literal_direct = literal - literal_resolved - enumerated_count
    harvested = facts.get('harvested') or {}
    own = sum(1 for value in harvested.values()
              if isinstance(value, tuple) and len(value) == 2 and value[1] == 'self')

    sources = channel_sources(facts, probe=probe)
    corroborated_items = [item for item in sources.values() if item['corroborated']]
    corroborated = len(corroborated_items)
    corroborated_strength = max((item['strength'] for item in corroborated_items), default=0.0)

    levels = []
    if corroborated:
        levels.append({
            'id': 'corroborated',
            'label': '两条路都对上的',
            'count': corroborated,
            'unit': '条',
            'strength': corroborated_strength,
            'can_prove': '静态和运行时各看见一次，两条路互不依赖',
            'cannot_prove': '对上的是名字，不是行为；门后逻辑仍然没审。'
                            '另外：只有探针给出了位置（probe JSON 的 sites）才有 corroboration_level，'
                            '没给位置就是 unknown——那说明这一档没算，不说明两条路不独立',
            'next_step': '优先看这几条，它们最不像我编的；但别把「对上了」当成「对上得有多实」',
        })
    levels.append({
        'id': 'literal',
        'label': '写死的名字',
        'count': literal_direct,
        'samples': sample_sites(facts, limit=2),
        'unit': '条',
        'strength': 1.0,
        'can_prove': '源码里逐字写着，file:line 能回到原文复核',
        'cannot_prove': '只覆盖写死的写法；拼出来的、算出来的它看不见',
        'next_step': '直接引用，但别当成完整清单',
    })
    if literal_resolved:
        levels.append({
            'id': 'literal-resolved',
            'label': '靠还原才认出的',
            'count': literal_resolved,
            'samples': sample_sites(facts, limit=2, only_resolved=True),
            'unit': '条',
            'strength': 0.9,
            'can_prove': '名字是从本包的字符串池、常量或常量对象里查出来的，原始出处还在源码里',
            'cannot_prove': '查得出不等于它真是通道；表可能被覆盖、字段可能同名不同义',
            'next_step': '能和运行时对上一个就更硬；对不上要回原文看那张表',
        })

    if enumerated_count:
        levels.append({
            'id': 'enumerated',
            'label': '穷举出来的',
            'count': enumerated_count,
            'samples': sample_sites(facts, limit=2, only_enumerated=True),
            'unit': '条',
            'strength': ENUM_STRENGTH_PROVEN,
            'weaker_strength': ENUM_STRENGTH_OPEN,
            'can_prove': '取值集合是源码里的字面量数组、拼法是字面量加参数，这几条都查过：'
                         '循环里没改过循环变量、数组没被 push/splice 改过、拼装函数只有一个表达式。'
                         f'三条全过的强度 {ENUM_STRENGTH_PROVEN}，和「靠还原」同档',
            'cannot_prove': '查的是「源码里没有那种写法」，不是「运行时一定只取这几个值」；'
                            f'有一条没过就降到 {ENUM_STRENGTH_OPEN}，名字照给但别当准的用。'
                            '每条名字的 enum_proof 里写着查了哪几条、哪条没过',
            'next_step': '看 enum_proof.failed：空的可以直接引用，非空的回原文看那个循环和拼装函数',
        })

    if probe and not probe.get('error'):
        levels.append({
            'id': 'runtime',
            'label': '程序自己报的',
            'count': len(probe.get('handlers') or []),
            'windows': len(probe.get('windows') or []),
            'unit': '条通道',
            'strength': 0.8,
            'can_prove': '探针连上主进程，直接读它注册了什么，不是猜的',
            'cannot_prove': '依赖它肯启动；启动配方每个应用不一样，换包要重摸',
            'next_step': '换另一个包先确认能起来，再信这一层',
        })
    elif probe:
        levels.append({
            'id': 'runtime',
            'label': '程序自己报的',
            'count': 0,
            'unit': '条通道',
            'strength': 0.0,
            'can_prove': '无——探针没跑通',
            'cannot_prove': '应用有没有通道，这一层什么都没说',
            'next_step': '先解决启动，再谈运行时',
        })

    if poke:
        levels.append({
            'id': 'poke',
            'label': '敲过一遍的',
            'count': None,
            'unit': '见分档',
            'strength': 0.6,
            'can_prove': '喂过不合规输入，看它是照收还是拒绝',
            'cannot_prove': '拒绝只证明有门；门后逻辑没审，参数校验仍然未知',
            'next_step': '被拦下的一档当「有门」用，另一档回去看代码',
        })

    levels.append({
        'id': 'computed',
        'label': '名字是算出来的',
        'count': len(facts['dynamic']),
        'unit': '处',
        'strength': 0.3,
        'can_prove': '知道这里有调用，名字不是写死的',
        'cannot_prove': '名字是什么，算不出来',
        'next_step': '人工看，这是研判的第一入口',
    })
    levels.append({
        'id': 'harvested',
        'label': '打捞出来的候选',
        'count': len(harvested),
        'own_count': own,
        'by_grade': {grade: sum(1 for name in harvested
                              if (facts.get('harvest_grades') or {}).get(name) == grade)
                     for grade in HARVEST_GRADES},
        'unit': '个',
        'strength': 0.2,
        'can_prove': '这些字符串长得像通道名',
        'cannot_prove': '长得像不等于就是；当线索用，别当结论',
        'next_step': '拿真名去比对，或者运行时验证',
    })
    levels.append({
        'id': 'unseen',
        'label': '没看见的',
        'count': None,
        'unit': '',
        'strength': 0.0,
        'can_prove': '无',
        'cannot_prove': '我这条路看不见，不代表它不在',
        'next_step': '换 REA 走语法级，或者运行时探针',
    })
    # 每层配一个机器能照做的动作，别只给一句人话
    layer_action = {
        'corroborated': 'cite_with_caveat',
        'literal': 'cite',
        'literal-resolved': 'spot_check_source',
        'runtime': 'trust_after_setup',
        'poke': 'review_handler',
        'computed': 'read_code',
        'harvested': 'triage',
        'unseen': 'escalate',
    }
    for level in levels:
        level['action'] = layer_action.get(level['id'], 'review')
    return levels


def confidence_ladder(facts, probe=None, poke=None):
    """把 confidence_levels 排成一张给人看的表。"""
    levels = confidence_levels(facts, probe=probe, poke=poke)

    def amount(level):
        count = level['count']
        if count is None:
            return '未知' if level['id'] == 'unseen' else level.get('unit') or '—'
        text = f"{count} {level.get('unit', '')}".strip()
        if level.get('own_count') is not None:
            text += f"，其中 {level['own_count']} 个是它自己写的"
        if level.get('windows') is not None:
            text += f" / {level['windows']} 个窗口"
        return text

    out = ['', '### 可信度分层', '',
           '同一条报告里的话，强度不是一样的。从上往下，越靠上越站得住。',
           '这张表也原样进了 `--format json` 的 `confidence` 字段，机器读同一套。', '']
    out.append('| 这一层 | 有多少 | 能证明什么 | 不能证明什么 / 下一步 |')
    out.append('| --- | --- | --- | --- |')
    for level in levels:
        out.append(f"| {level['label']} | {amount(level)} | "
                   f"{level['can_prove']} | {level['cannot_prove']}；{level['next_step']} |")
    out.append('')

    # 每层给一两条能自己查的样本：有样本才叫「你能核对」，没样本只能「你信我」
    samples = [(level['label'], level['samples']) for level in levels
               if level.get('samples')]
    if samples:
        out.append('**抽两条自己看**（打不开就别信这一行）：')
        out.append('')
        for label, items in samples:
            for item in items[:2]:
                out.append(f"- {label}：`{item['name']}` @ `{item['where']}`")
        out.append('')
    out.append('> 这张表里的任何一层都不该被单独引用。报告是给人做判断用的地图，不是判决书。')
    out.append('> 每层会重叠——同一个名字可能既靠还原查出来，又被运行时看见，两行都会算它。')
    out.append('> 所以别把这一列加起来当总数，它不是分类，是几张不同的标签。')
    out.append('> 每个名字各自的来源记在 JSON 的 `evidence` 里——一个包里，写死的名字和')
    out.append('> 只在运行时见过的名字不是一回事，混在一起会互相借光。')
    out.append('')
    return out


def baseline_delta(facts, baseline):
    """跟上次比，多了什么、少了什么、哪里变了。

    基线不只看发现，也看通道名——一个包升级之后新开一扇门，
    那是比「多一条可疑项」更要紧的事。
    """
    old_channels = set(baseline.get('channels') or ())
    new_channels = set(facts.get('channels') or ())
    old_findings = {(text, where) for _l, text, where in baseline.get('findings') or ()}
    new_findings = [f for f in audit_asar(facts) if (f[1], f[2]) not in old_findings]
    return {
        'added_channels': sorted(new_channels - old_channels),
        'removed_channels': sorted(old_channels - new_channels),
        'new_findings': new_findings,
        'baseline_channels': len(old_channels),
    }


def render_baseline(delta):
    out = ['', '## 跟基线比', '']
    if not delta['baseline_channels'] and not delta['new_findings']:
        out.append('- 基线是空的，等于是第一次跑。这次的结果已经可以当基线用')
        out.append('')
        return out
    out.append(f"- 基线里有 {delta['baseline_channels']} 条通道")
    added, removed = delta['added_channels'], delta['removed_channels']
    if added:
        out.append(f'- 新冒出来 {len(added)} 条：')
        for name in added[:12]:
            out.append(f'  - `{name}`')
        if len(added) > 12:
            out.append(f'  - 还有 {len(added) - 12} 条')
    else:
        out.append('- 没有新通道')
    if removed:
        out.append(f'- 基线里有、这次没了的 {len(removed)} 条：')
        for name in removed[:12]:
            out.append(f'  - `{name}`')
        if len(removed) > 12:
            out.append(f'  - 还有 {len(removed) - 12} 条')
        out.append('> 名字没了可能是删了，也可能是换了写法认不出——这个工具分不开这两件事。')
    out.append('')
    return out


def input_sha256(path):
    """输入文件的 sha256。读不动就返回 None——不编一个值出来。"""
    try:
        digest = hashlib.sha256()
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b''):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def fingerprint_of(target, channel_names, params=None):
    """这份报告的可复算指纹。

    同样输入 + 同样版本 + 同样参数 → 同样的值。别人重跑能对上，才叫证据；
    对不上就是有人改了输入、换了版本，或者我这边行为漂了。

    注意 schema 别再写死：以前这里硬编码 'asar/17'，之后升到 18/19/20 都没跟上，
    指纹里的 schema 一直报旧值。现在由主模块注入 SCHEMA，selfcheck 盯着两边一致。
    """
    payload = {
        'input_sha256': input_sha256(target),
        'version': VERSION,
        'schema': SCHEMA,
        'params': params or {},
        'channels': sorted(channel_names),
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')
    payload['digest'] = hashlib.sha256(blob).hexdigest()
    payload['algorithm'] = 'sha256(canonical-json)'
    return payload


def sink_table(facts, hit):
    """把「每条 API 的凭据」渲染成一张表。

    每一行都是人能直接核的：档位说这条有多硬，位置说去哪看，跳数和经过说
    它是怎么爬过来的。报告里承诺的「跳到那一行」，靠的就是 at 这一列。
    """
    ev = facts.get('channel_sink_evidence') or {}
    rows = []
    for name in sorted(hit):
        for api in sorted(hit[name]):
            item = (ev.get(name) or {}).get(api) or {}
            tier = item.get('tier') or '—'
            at = item.get('at') or '—'
            hops = item.get('hops')
            via = item.get('via') or '—'
            depth = item.get('depth') or '—'
            rows.append('| `%s` | `%s` | %s | %s | %s | %s | %s | %s |'
                        % (name, api, danger_kind_of(api), tier, depth, at,
                           '—' if hops is None else hops, via))
    out = ['| 通道 | API | 类别 | 档位 | 证据 | 位置 | 跳数 | 经过 |',
           '| --- | --- | --- | --- | --- | --- | --- | --- |']
    out.extend(rows)
    return out


def sink_table_legend():
    """档位怎么读——这张表不解释，人就没法用它判断。"""
    return [
        '- `direct`：处理函数自己直接调，最硬',
        '- `name_confirmed`：语法树和名字级两条口径都报，但没记下路径',
        '- `chain`：同文件函数链爬到的，跳数见「跳数」列',
        '- `ambiguous`：经过同名多义的函数（压缩产物里 f/y/m 满地重名），'
        '**可能是对的，也可能跟错了身子**——「经过」列会标「同名多义」',
        '- `ast_only`：只有语法树看见，名字级没有。这一档最不可信',
        '',
        '「证据」三段的区别：`full` 跳数和经过都记下来了，能复现这条链；'
        '`locate_only` 有位置能跳过去看，但链路没记全；`name_only` 只有 API 名，'
        '连位置都没有。软档本来就不可信，但不可信到什么程度得能看出来。',
        '',
        '「位置」是**处理函数体**的起点，格式 `文件:行@字符偏移`。'
        '压缩过的包整个文件就几行（obsidian 47 条通道全落在 main.js:66 那一行），'
        '所以带偏移——拿偏移在那一行里定位，比只给行号有用得多。',
    ]


def count_sink_rows(md_text, section='## 按语法树再走一遍'):
    """数某一节 sink 表格里的条目数。

    这是防「报告少渲染」的尺子：md 的条目数必须等于 JSON 里
    `channel_sink_evidence` 的条目数。加它是因为真出过一次——0.98.0 把
    tier/at/hops 只写进了 JSON，md 那节还是一条 via 摘要，CHANGELOG 却承诺
    「跳到那一行」。产品承诺和产品不一致，而当时 424 个用例全绿。
    """
    import re
    total = 0
    inside = False
    for line in md_text.split('\n'):
        if line.strip() == section:
            inside = True
            continue
        if line.startswith('## ') and line.strip() != section:
            inside = False
            continue
        # 只数 7 列的主表（通道/API/类别/档位/位置/跳数/经过）。
        # 同一节后面还有个 5 列的「借来的 API」小表，那不是主结论，别混进来。
        if inside and re.match(r'^\| `[^`]+` \| `[^`]+` \|', line):
            if len(line.split('|')) == 10:
                total += 1
    return total


def render_asar(target, facts, file_count, total_bytes, show_all=False, findings=None,
                probe=None, poke=None, baseline=None):
    out = ['# Electron 能力面清单（粗扫）', '']
    out.append(f'- 目标：`{os.path.abspath(target)}`')
    out.append(f'- {file_count} 个文件，{total_bytes / 1024 / 1024:.1f} MB，其中 {facts["scanned"]} 个提到 IPC')
    out.append(f'- {stamp()}')
    fp = fingerprint_of(target, [n for n, _ in facts['handlers'] + facts['invokes']
                                 + facts['exposes']])
    out.append(f"- 复算指纹：`{fp['digest']}`（输入 {fp['input_sha256'][:16] if fp['input_sha256'] else '读不到'}…，"
               f"版本 {fp['version']}；同样的输入和参数重跑，应该得到同一个值）")
    out.append('')
    out.append('## 这份报告能信多少')
    out.append('')
    out.append('这是字符串级粗扫：只认写死在源码里的名字，不建语法树，跟着代码走不通。')
    out.append('要准的，先跑 `rea analyze-javascript-application`，再把 Evidence 喂给本工具。')
    strong = [h for h in facts['obfuscation'] if h[2] == 'strong']
    weak = [h for h in facts['obfuscation'] if h[2] == 'weak']
    if strong:
        out.append('')
        out.append('这包动过手脚。下面的名字可能只是一部分，别拿它当完整清单。')
    out.append('')
    out.extend(confidence_ladder(facts, probe=probe, poke=poke))
    if baseline is not None:
        out.extend(render_baseline(baseline_delta(facts, baseline)))

    # 一条都没扫到的时候，最容易被读成「这包干净」。
    # 那是我这套办法的空白，不是这包的结论，得顶在最前面说清楚。
    if not (facts['exposes'] or facts['handlers'] or facts['invokes']):
        harvested = facts.get('harvested') or {}
        own = sum(1 for _where, kind in harvested.values() if kind == 'self')
        blocked = []
        if facts['obfuscation']:
            blocked.append(f'混淆痕迹 {len(facts["obfuscation"])} 处')
        if facts['dynamic']:
            blocked.append(f'名字是拼出来的 {len(facts["dynamic"])} 处')
        if harvested:
            blocked.append(f'打捞兜底只捞到 {len(harvested)} 个候选，其中 {own} 个是这个应用自己写的')
        out.append('## 一条字面通道都没看见')
        out.append('')
        out.append('先别读成「这个包里没有」。这句的意思是：我这条路走不通。')
        out.append('粗扫只认写死的名字。名字是拼出来的、从别处算出来的、或者整个文件被压过，我一律看不见。')
        out.append('')
        if blocked:
            out.append('这次实际卡住的地方：')
            for line in blocked:
                out.append(f'- {line}')
        else:
            out.append('这次连混淆和拼接都没认出来——更可能是我认不出它的写法，不是它简单。')
        out.append('')
        out.append('所以这份报告对「有没有通道」这个问题，答案是「不知道」。')
        out.append('想拿到答案只有两条路：跑一遍 REA 走语法级，或者把打捞出来的候选一条条自己看。')
        out.append('')

    if facts['obfuscation']:
        out.append('## 混淆痕迹')
        out.append('')
        out.append('解不开，但认得出。强的那几条说明代码被处理过；弱的多半只是库的写法。')
        out.append('')
        shown = (strong + weak) if show_all else (strong + weak)[:8]
        for name, where, level in shown:
            tag = '强' if level == 'strong' else '弱'
            out.append(f'- [{tag}] {name}  `{where}`')
        rest = len(facts['obfuscation']) - len(shown)
        if rest > 0:
            out.append(f'- 还有 {rest} 处没列，加 `--all` 看全')
        out.append('')
        out.append('> 一个两万文件的包里 `new Function` 出现几十次是常态，那不是混淆。')

    if facts.get('recovered'):
        out.append('## 从 sourcemap 翻回来的')
        out.append('')
        out.append(f'包里带着 {len(facts["recovered"])} 份没压过的源码，上面有几行是从它们里扫到的：')
        out.append('')
        for rel in facts['recovered'][:6]:
            out.append(f'- `{rel}`')
        if len(facts['recovered']) > 6:
            out.append(f'- 还有 {len(facts["recovered"]) - 6} 份')
        out.append('')
        out.append('> 这是这包自己把源码交出来的，不是猜的。')
        out.append('')

    out.append('## 窗口设置')
    if facts['prefs']:
        for key, (value, where) in sorted(facts['prefs'].items()):
            out.append(f'- `{key}` = {value}  `{where}`')
    else:
        out.append('- 没扫到 webPreferences，可能压根不是 Electron，也可能写得绕')
    for value, where in facts['preloads']:
        out.append(f'- preload = `{value}`  `{where}`')
    for key in ('nodeIntegration', 'contextIsolation', 'sandbox'):
        if key not in facts['prefs']:
            out.append(f'- 没扫到 `{key}`，可能是默认值，也可能在别处写')
    out.append('')

    out.append('## preload 挂出去的名字')
    if facts['exposes']:
        for value, where in facts['exposes']:
            out.append(f'- `window.{value}`  `{where}`')
    else:
        out.append('- 没扫到 contextBridge.exposeInMainWorld')
    out.append('')

    out.append('## 通道')
    out.append('')
    out.append('| 通道 | 主进程 | 页面侧 |')
    out.append('| --- | --- | --- |')
    names = sorted({n for n, _ in facts['handlers']} | {n for n, _ in facts['invokes']})
    host = defaultdict(list)
    page = defaultdict(list)
    limit = len(names) if show_all else 30
    for name, where in facts['handlers']:
        host[name].append(where)
    for name, where in facts['invokes']:
        page[name].append(where)
    for name in names[:limit]:
        h = ', '.join(f'`{w}`' for w in host.get(name) or ['—'])
        p = ', '.join(f'`{w}`' for w in page.get(name) or ['—'])
        out.append(f'| `{name}` | {h} | {p} |')
    if not names:
        out.append('| — | — | — |')
    elif len(names) > limit:
        out.append(f'| … 还有 {len(names) - limit} 条没列 | 加 `--all` 看全 | |')
    out.append('')
    if len(names) > 12:
        groups = defaultdict(int)
        for name in names:
            groups[re.split(r'[:/.]', name)[0] or name] += 1
        out.append('按前缀分组：' + '，'.join(f'`{k}` {v} 条' for k, v in
                                            sorted(groups.items(), key=lambda kv: -kv[1])[:8]))
        out.append('')

    caps = facts.get('capability') or {}
    if caps:
        flagged = sorted(name for name, info in caps.items()
                         if info['level'] == 'high-capability-no-guard-seen')
        guarded = sorted(name for name, info in caps.items()
                         if info['level'] == 'high-capability-guard-seen')
        quiet = len(caps) - len(flagged) - len(guarded)
        out.append('## 每条通道能碰到什么')
        out.append('')
        out.append('这是能力面，不是风险评级：看见 `fs.writeFile` 只说明这里能写文件，'
                   '不说明它会被滥用；看见 `senderFrame` 只说明有人写了校验，不说明校验有效。')
        out.append('')
        out.append(f'- 看见高危能力（命令执行 / 文件读写 / 动态求值）、**没看见**校验字样：{len(flagged)} 条')
        for name in flagged[:15]:
            out.append(f"  - `{name}`：{'、'.join(caps[name]['apis'])}  `{caps[name]['where']}`")
        out.append(f'- 看见高危能力、也看见校验字样：{len(guarded)} 条')
        for name in guarded[:10]:
            out.append(f"  - `{name}`：{'、'.join(caps[name]['apis'])} + {'、'.join(caps[name]['guards'])}")
        out.append(f'- 处理函数体里什么都没看见：{quiet} 条'
                   '——多半是转发壳，真干活在服务层，字符串级跳不过去')
        out.append('')
        out.append('> 只扫注册处那一个函数体，不跟调用链。所以「没看见」不等于「没有」，'
                   '更别把它读成「这条通道安全」。')
        out.append('')

    unattributed = facts.get('channel_unattributed')
    if unattributed:
        out.append(f'- 还有 **{unattributed} 处注册点**的名字是运行时才成形的，静态解不出来——'
                   '这些通道没进上面的清单，别把上面的数当全集。')
        out.append('')

    # 跟了调用链之后的结果（词法+调用图，含跨文件一到两跳）。
    # 和上面那节口径不同：上面是字符串级只看注册函数体，这里是真跟到函数和图里。
    sinks = facts.get('channel_sinks')
    if sinks is not None:
        hit = {name: apis for name, apis in sinks.items() if apis}
        out.append('## 跟了调用链之后')
        out.append('')
        out.append(f'顺着处理函数往下走（含同文件调用链和跨文件一跳、两跳），{len(hit)} 条通道能碰到危险 API。')
        out.append('')
        if hit:
            out.extend(sink_table(facts, hit))
            out.append('')
            out.extend(sink_table_legend())
        else:
            out.append('  - 一条都没有。这不等于干净：可能是转发壳，也可能名字是拼出来的。')
        out.append('')
        out.append('> 这条只说明「能碰到」，不说明「能被滥用」。参数从哪来、校验拦不拦得住，'
                   '要另一套分析，本报告不下结论。')
        out.append('')

    # 语法树口径：成员调用、方括号、别名、回调都能连边，比上面那节准。
    ast_sinks = facts.get('channel_sinks_ast')
    if ast_sinks is not None:
        hit = {name: apis for name, apis in ast_sinks.items() if apis}
        out.append('## 按语法树再走一遍')
        out.append('')
        out.append(f'这次不靠名字猜：建了语法树，成员调用、`fs["readFileSync"]`、'
                   f'别名、回调传参都算一条边。{len(hit)} 条通道能碰到危险 API。')
        out.append('')
        if hit:
            out.extend(sink_table(facts, hit))
        else:
            out.append('  - 一条都没有。只说明这个包里没连到，不是确认没有。')
        out.append('')
        out.append('> 树只跟同一份文件；跨文件的调用还连不过去，这条缺口写在 '
                   '`docs/known-wrong.md`。')
        ambiguous = facts.get('channel_sinks_ambiguous') or []
        if ambiguous:
            out.append('')
            out.append('下面这些通道的结论要**经过同名多义**的函数（压缩产物里 f/y/m 满地重名）：'
                       '可能是对的，也可能跟错了身子。列出借来的 API 和位置，'
                       '复核时按位置逐条看——别按通道名打包信或打包不信。')
            out.append('')
            ev = facts.get('channel_sink_evidence') or {}
            out.append('| 通道 | 借来的 API | 档位 | 位置 | 经过 |')
            out.append('| --- | --- | --- | --- | --- |')
            for name in ambiguous:
                item = ev.get(name) or {}
                borrowed = [(api, info) for api, info in item.items()
                            if (info or {}).get('tier') in ('ambiguous', 'ast_only')]
                if not borrowed:
                    out.append(f'| `{name}` | — | — | — | — |')
                    continue
                for api, info in sorted(borrowed):
                    out.append('| `%s` | `%s` | %s | %s | %s |'
                               % (name, api, info.get('tier') or '—',
                                  info.get('at') or '—', info.get('via') or '—'))
        out.append('')

    tainted = facts.get('channel_tainted')
    if tainted is not None:
        hit = {name: flows for name, flows in tainted.items() if flows}
        out.append('## 外部输入能走到危险参数')
        out.append('')
        if hit:
            out.append(f'{len(hit)} 条通道里，请求带进来的东西确实到了危险调用的参数上。'
                       '这批是要动手看的，不是提醒。')
            for name in sorted(hit):
                bits = []
                for item in hit[name][:3]:
                    if isinstance(item, (list, tuple)) and len(item) >= 2:
                        bits.append(f'{item[0]}({item[1]})')
                    else:
                        bits.append(str(item))
                out.append(f'  - `{name}`：{"、".join(bits)}')
        else:
            out.append('一条都没有。这不等于安全：可能校验拦住了，也可能是我没跟到。')
        out.append('')
        out.append('> 判据只有一种：外部输入经赋值、回调、循环变量、catch 变量流到危险参数。'
                   '跨函数传参只跟到形参对应的实参，不做完整的别名分析。')
        out.append('')


    harvested = facts.get('harvested') or {}
    if harvested:
        grades = facts.get('harvest_grades') or {}
        mine = {k: v for k, v in harvested.items() if v[1] == 'self'}
        others = {k: v for k, v in harvested.items() if v[1] != 'self'}
        out.append('## 长得像通道的字符串')
        out.append('')
        out.append(f'调用点认不出了，但名字本身还躺在字符串里。捞上来 {len(harvested)} 个，'
                   f'其中 {len(mine)} 个是这个应用自己写的。')
        out.append('')
        # 一堆线索和一张能用的清单，差别就在这一步：先按能判的事实分档，再按档看。
        by_grade = {grade: sorted(name for name in harvested if grades.get(name) == grade)
                    for grade in HARVEST_GRADES}
        out.append('| 档位 | 数量 | 这是什么 |')
        out.append('| --- | --- | --- |')
        out.append(f'| 就是通道 | {len(by_grade["channel"])} | 和静态看见的通道名对上了，不用再猜 |')
        out.append(f'| 在含 IPC 的文件里 | {len(by_grade["near-ipc"])} | 名字躺在注册表或调用旁边，可疑度最高 |')
        out.append(f'| 同前缀成簇 | {len(by_grade["clustered"])} | 同前缀 ≥3 个，像一张名字表 |')
        out.append(f'| 零星 | {len(by_grade["stray"])} | 只在别处出现，最可能是噪音 |')
        out.append('')
        for grade, title in (('channel', '对上的'), ('near-ipc', '在含 IPC 的文件里')):
            if not by_grade[grade]:
                continue
            out.append(f'### {title}')
            out.append('')
            for value in by_grade[grade][:20]:
                out.append(f'- `{value}`  `{harvested[value][0]}`')
            if len(by_grade[grade]) > 20:
                out.append(f'- 还有 {len(by_grade[grade]) - 20} 个')
            out.append('')
        noise = by_grade['clustered'] + by_grade['stray']
        if noise:
            out.append(f'另外 {len(noise)} 个是成簇或零星的候选（`tool`、`js` 这类前缀最多），'
                       '噪音大，默认只报数量；要看全加 `--all`。')
            out.append('')
        out.append('> 前两档值得先看，后两档先当噪音。'
                   '分档只用了能判的事实（是不是通道名、在不在含 IPC 的文件里、同前缀几个），'
                   '没做语义猜测——猜错了比不分档更坏。')
        out.append('')

    out.append('## 没看清的地方')
    out.append('')
    out.append('这张表只能证明哪些看清了，不能证明没有什么。')
    out.append('')
    if facts['native_files']:
        out.append(f"- 这包带着 {len(facts['native_files'])} 个 native 模块，越界、泄漏只可能在它们里面：")
        for rel in facts['native_files'][:8]:
            out.append(f"  - `{rel}`")
        nimports = facts.get('native_imports') or {}
        if nimports:
            out.append('- 其中这些模块的导入表里，有危险 Windows API（strcpy/system 这类）：')
            for rel, hits in list(nimports.items())[:8]:
                out.append(f"  - `{rel}`：{'、'.join(hits)}")
        elif facts['native_files']:
            out.append('- 这些模块的导入表读不出来（.node 多半是打包/加壳的，开头不是 MZ）。'
                       '读不出来是「读不到」，不是「没有危险导入」')
        out.append('- 上面那张表跟它们没关系，两边得分开查')
    else:
        out.append('- 没有 native 模块，越界这类本来就不该出在 JS 这层')
    if facts.get('nested_asar'):
        out.append(f"- 里面有 {len(facts['nested_asar'])} 个套着的 asar，这一层没拆开看：")
        for rel in facts['nested_asar'][:5]:
            out.append(f"  - `{rel}`")
        out.append('- 要看得先把它们解出来，单独跑一遍')

    # IPC 之外的能力面（P1-5）：主线只进计数 + 样本，全量进 JSON。
    asurf = facts.get('attack_surface') or {}
    if any(asurf.values()):
        labels = {
            'shell-open': 'shell 打开外部链接/文件',
            'exec-js': 'executeJavaScript 注入',
            'permission-handler': '权限请求处理器',
            'custom-protocol': '自定义协议',
            'deep-link': '深链 / 第二实例',
            'webview': 'webview / WebContentsView',
        }
        out.append('')
        out.append('## 能力面（IPC 之外）')
        out.append('')
        out.append('这里只记「这个面在源码里出现过」，不判它会怎么用。')
        out.append('')
        for facet in sorted(asurf):
            hits = asurf[facet]
            if not hits:
                continue
            label = labels.get(facet, facet)
            out.append(f'- **{label}**：{len(hits)} 处')
            for hit in hits[:3]:
                arg = hit.get('arg')
                tag = ''
                if arg == 'literal':
                    tag = '（写死的值）'
                elif arg == 'variable':
                    tag = '（活值，可能来自外部）'
                out.append(f"  - `{hit['where']}`{tag}：{hit['snippet']}")
        out.append('')

    # precise 第三列：tree-sitter 精查层，opt-in。这是「更强一档证据」，不是确认。
    if 'precise_sinks' in facts:
        out.append('## precise 第三列（tree-sitter 精查）')
        out.append('')
        out.append('跨文件 / 类方法才连得上的那条链，粗扫看不见；这里是更强一档证据，'
                   '不是「确认」。')
        out.append('')
        ps = facts.get('precise_sinks')
        if ps is None:
            out.append('- precise 没跑成（tree-sitter 没装或报错），这一列空着。'
                       '`pip install ipcsurface[precise]`')
        elif not ps:
            out.append('- precise 跑完了，没多认出任何粗扫漏掉的危险 API。')
        else:
            for ch, apis in list(ps.items())[:20]:
                out.append(f'- `{ch}`：{"、".join(apis)}')
        out.append('')
    if facts['dynamic']:
        for what, where in facts['dynamic'][:20]:
            out.append(f'- 名字是算出来的不是写死的：`{what}`  `{where}`')
    else:
        out.append('- 没扫到算出来的通道名；但不等于没有，字符串拼法有无数种')
    out.append('- 混淆过、压过的代码，这里一条都认不出来')
    out.append('- 内存层面不看，越界、泄漏要在运行时或者 native 那边查')
    out.append('')
    out.append('> 粗扫只用来决定要不要认真查，不用来签字。')
    if findings:
        out.append('')
        out.append('## 可疑项')
        order = {'high': 0, 'medium': 1}
        for level, text, where in sorted(findings, key=lambda f: order.get(f[0], 9))[:10]:
            out.append(f'- [{level}] {text}  `{where}`')
    return '\n'.join(out)
