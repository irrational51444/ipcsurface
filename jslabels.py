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
