"""报告要用的「说法」：时间戳、危险 API 归类、候选分档的名字。

这些是报告和 JSON 都要用的标签层，跟扫描/分析没关系，所以单独放。
ipcsurface 会原样重新导出，老调用方不用改。

注意：这里不许 import ipcsurface —— 否则两边互相引用，导入顺序一变就炸。
真需要版本号时，由调用方传进来（见 stamp(version)）。
"""
import datetime

# 危险 API 归到哪一类。键是「报告里怎么写」，值是 API 名。
DANGER_KIND_MAP = {
    '文件写': ('writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
             'createWriteStream', 'unlink', 'unlinkSync', 'rmSync', 'rename', 'renameSync',
             'copyFile', 'copyFileSync', 'mkdir', 'mkdirSync', 'mkdtemp', 'mkdtempSync',
             'rmdir', 'rmdirSync', 'truncate', 'truncateSync'),
    '文件读': ('readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync',
             'lstat', 'stat', 'existsSync'),
    '命令执行': ('exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'),
    '网络': ('fetch', 'request'),
    '动态求值': ('eval', 'Function'),
}

# 捞出来的候选按「有多像通道」分档，档名就是报告里的那一列。
HARVEST_GRADES = ('channel', 'near-ipc', 'clustered', 'stray')

# 能力标签：把危险 API 归到「这条通道能碰到什么能力」，给通道打标签用。
# 和 DANGER_KIND_MAP 的区别：那个是「危险调用的类别」，这个是「能力面」——
# fs / child_process / shell / path / network / eval。一条通道可能同时有多个标签。
RISK_CAPABILITY = {
    'fs': ('writeFile', 'writeFileSync', 'appendFile', 'appendFileSync',
           'createWriteStream', 'unlink', 'unlinkSync', 'rmSync', 'rename', 'renameSync',
           'copyFile', 'copyFileSync', 'mkdir', 'mkdirSync', 'mkdtemp', 'mkdtempSync',
           'rmdir', 'rmdirSync', 'truncate', 'truncateSync',
           'readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync',
           'lstat', 'stat', 'existsSync'),
    'child_process': ('exec', 'execSync', 'spawn', 'spawnSync', 'execFile', 'execFileSync'),
    'shell': ('openExternal', 'openPath', 'showItemInFolder'),
    'path': ('join', 'resolve', 'normalize', 'basename', 'dirname', 'extname'),
    'network': ('fetch', 'request'),
    'eval': ('eval', 'Function'),
}

# 标签的顺序固定：报告和 JSON 里都按这个排，别让集合顺序随机。
RISK_LABEL_ORDER = ('fs', 'child_process', 'shell', 'path', 'network', 'eval')


def risk_labels(apis):
    """一组危险 API → 能力标签（fs / child_process / shell / path / network / eval）。"""
    found = set()
    for api in apis:
        for label, names in RISK_CAPABILITY.items():
            if api in names:
                found.add(label)
    return [label for label in RISK_LABEL_ORDER if label in found]


# 「像不像通道名」只看字符形态，不猜语义——猜错了比不分档更坏。
# 通道名的典型形态：a:b、camelCase、kebab-case、UPPER_SNAKE、x.y；
# 代码片段/噪音的典型形态：带空格、分号、括号、引号、尖括号。
_CODE_LIKE_CHARS = ' \t\n\r;(){}[]<>|&"\'`'


def looks_like_channel(name):
    """字符形态判断：像不像一个通道名。零上下文，纯看字符串本身。"""
    if not name or len(name) < 2 or len(name) > 200:
        return False
    return not any(ch in name for ch in _CODE_LIKE_CHARS)


def harvest_confidence(name, grade=None, near_call=False):
    """给一个候选字符串打「像 IPC」的可信度 0~1，并给出可解释的理由。

    不训练黑盒模型：用能解释的加权特征，理由一起给出来，读的人知道为什么。
    权重是先验，用 golden 数据校准（docs/harvest-classifier.md）。
    """
    score = 0.0
    reasons = []
    if grade == 'channel':
        score += 0.55
        reasons.append('和静态通道名重合 +0.55')
    elif grade == 'near-ipc':
        score += 0.20
        reasons.append('在含 IPC 的文件里 +0.20')
    elif grade == 'clustered':
        score += 0.10
        reasons.append('同前缀成簇 +0.10')
    if near_call:
        score += 0.15
        reasons.append('紧挨调用点 +0.15')
    if looks_like_channel(name):
        score += 0.15
        reasons.append('形态像通道名 +0.15')
    else:
        score -= 0.40
        reasons.append('形态像代码片段 -0.40')
    return max(0.0, min(1.0, score)), reasons


def danger_kind_of(api):
    """危险 API 归到哪一类；不认识就写「其它」，别硬猜。"""
    for kind, names in DANGER_KIND_MAP.items():
        if api in names:
            return kind
    return '其它'


def stamp(version=None):
    """报告里带生成时间和版本——审出来的东西要能对上号。"""
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M')
    if version:
        return f'生成于 {now}，ipcsurface {version}'
    return f'生成于 {now}'
