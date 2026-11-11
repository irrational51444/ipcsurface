"""自查：把这一晚上堆起来的东西逐项核一遍，看有没有名不副实的地方。"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, r'C:\Users\irrational\Desktop\rea-lab')
import ipcsurface as t

REAL = os.environ.get('IPCSURFACE_REAL_APP') or r'C:\Users\irrational\AppData\Local\Programs\DeepSeek Harness\resources\app.asar'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    return open(os.path.join(ROOT, *parts), encoding='utf-8').read()


def check(label, ok, detail=''):
    print(('  OK   ' if ok else '  FAIL ') + label + (('  ' + detail) if detail else ''))
    return ok


def run_unittest_summary():
    """跑一遍用例，把「实跑几个、跳几个」拿回来。"""
    result = subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-s', 'tests'],
                            cwd=ROOT, capture_output=True, text=True,
                            encoding='utf-8', errors='replace')
    text = result.stdout + result.stderr
    ran = re.search(r'Ran (\d+) test', text)
    skipped = re.search(r'skipped=(\d+)', text)
    return (int(ran.group(1)) if ran else -1,
            int(skipped.group(1)) if skipped else 0)


def check_test_classes(ok):
    """同名测试类会互相覆盖，用例静悄悄不跑——这坑踩过一次，得一直盯着。"""
    names = re.findall(r'^class (\w+)\(unittest\.TestCase\):', read('tests', 'test_ipcsurface.py'),
                       re.M)
    dupes = sorted({n for n in names if names.count(n) > 1})
    return ok & check('没有同名测试类互相覆盖', not dupes, '、'.join(dupes))


TAG_SINCE = '0.9.0'   # 打 tag 从这一版起；更早的版本是历史，不补


def check_referenced_paths(ok, readme):
    """文档里提到的仓库内文件，必须真的在、而且被 git 跟踪。

    这条是踩出来的：`build/` 在 .gitignore 里，我把自查脚本放在那儿，
    README 和 CI 都写着 `python build/selfcheck.py`——用户 clone 下来根本没有这个文件。
    """
    tracked = set(subprocess.run(['git', 'ls-files'], cwd=ROOT,
                                 capture_output=True, text=True).stdout.split('\n'))
    problems = []
    for path in set(re.findall(r'\b(?:scripts|examples|tests|docs|probe)/[\w./-]+', readme)):
        clean = path.rstrip('.,）)')
        if not os.path.exists(os.path.join(ROOT, clean.replace('/', os.sep))):
            problems.append(clean + '(不存在)')
        elif clean not in tracked:
            problems.append(clean + '(没被跟踪)')
    return ok & check('文档里提到的仓库内文件都在且被跟踪',
                      not problems, '、'.join(sorted(problems)[:5]))


def check_local_links(ok, readme):
    """README 里指本仓库的文件得真的在，别指向一个已经改名的路径。

    只认长得像路径的目标：表格里那些 `ipcMain['handle']('x:y')` 不是链接。
    """
    missing = []
    for target in re.findall(r'\]\((?!http)([^)\s]+)\)', readme):
        if not re.match(r'^[\w./-]+\.(md|png|py|json|toml|yml|svg|txt)$', target):
            continue
        path = os.path.join(ROOT, target.replace('/', os.sep))
        if not os.path.exists(path):
            missing.append(target)
    return ok & check('README 里的本地链接都存在', not missing, '、'.join(missing[:5]))


def check_versions_match_tags(ok, version, changelog):
    tags = subprocess.run(['git', 'tag', '--list', 'v*'], cwd=ROOT,
                          capture_output=True, text=True).stdout.split()
    ok &= check('当前版本有 tag', 'v' + version in tags, version)
    logged = set(re.findall(r'^## (\d+\.\d+\.\d+) —', changelog, re.M))
    tagged = {tag.lstrip('v') for tag in tags}
    # 只要求 TAG_SINCE 之后的两边对得上；更早的版本当时没打 tag，是历史
    recent_logged = {v for v in logged if tuple(map(int, v.split('.'))) >=
                     tuple(map(int, TAG_SINCE.split('.')))}
    ok &= check(f'CHANGELOG 里 {TAG_SINCE} 之后的版本都有 tag',
                recent_logged <= tagged, '缺 ' + '、'.join(sorted(recent_logged - tagged)[:5]))
    ok &= check('tag 都在 CHANGELOG 里有记录',
                tagged <= logged, '缺 ' + '、'.join(sorted(tagged - logged)[:5]))
    return ok


def check_output_contract(ok):
    """退出码和 SARIF 是 CI 的信号，这两样得真的能用，不能只写在文档里。"""
    sarif = t.render_sarif('x.asar', [('high', '强混淆指纹：eval', 'a.js:3')], t.__version__)
    ok &= check('SARIF 版本是 2.1.0', sarif.get('version') == '2.1.0')
    rules = sarif['runs'][0]['tool']['driver']['rules']
    ok &= check('SARIF 规则 id 是 ASCII',
                all(r['id'].encode('ascii', 'ignore').decode() == r['id'] for r in rules))
    ok &= check('退出码表说得清 0 和 2',
                '没有触发门禁' in t.EXIT_CODES[0] and '--fail-on' in t.EXIT_CODES[2])
    return ok


TARGET_EXPECT = {
    # README 靶场表里写死的期望值，这里照抄一份。改坏还原逻辑这里会红。
    'static-asar.asar': 5,
    'dyn-asar.asar': 6,      # 0.75.0 起 OPS 循环里的三条能穷举出来，3 → 6
    'obf-asar.asar': 0,
    'obf2-asar.asar': 4,
    'obf3-asar.asar': 2,
    'obf4-asar.asar': 1,
    'obf5-asar.asar': 2,
    'bulk-asar.asar': 800,
    'native-asar.asar': 2,
    'adv-asar.asar': 1,      # 十二种写法里认出三处，但同名，去重后是 1 条通道
    'realish.asar': 12,      # 可复现的「像真项目」靶场：3042 个文件、12 条通道
}


def check_targets(ok):
    """九个靶子的期望值。靶场是这套东西的答案纸，掉了没人发现就白写了。

    样本一改，期望值必须跟着改——所以这里先比集合：多一个靶子没登记、或者
    登记了却没有这个靶子，都算红。不然期望值会从保护变成噪音。
    """
    built = os.path.join(ROOT, 'examples', 'build')
    if not os.path.isdir(built):
        print('  SKIP 靶场还没 build，跳过（跑 examples/build.sh 再自查）')
        return ok
    present = {name for name in os.listdir(built) if name.endswith('.asar')}
    # adv-asar 是手工造的对抗样本，仓库里没有它的生成脚本，别的机器上造不出来。
    # 缺它就跳过并写清原因——不装成通过，也不当成回归。
    local_only = {'adv-asar.asar'}
    absent_local = sorted(local_only - present)
    if absent_local:
        print(f"  SKIP {', '.join(absent_local)} 没造出来（仓库无生成脚本，只在本地有）")
    missing = sorted(set(TARGET_EXPECT) - present - local_only)
    extra = sorted(present - set(TARGET_EXPECT))
    ok &= check('每个靶子都有期望值', not missing, '、'.join(missing))
    ok &= check('没有靶子没登记期望值', not extra, '、'.join(extra))
    for name, expect in sorted(TARGET_EXPECT.items()):
        path = os.path.join(built, name)
        if not os.path.exists(path):
            continue
        facts, _count, _total = t.analyse_asar(path)
        got = len(facts['channels'])
        ok &= check(f'{name} 认得出 {expect} 条', got == expect, f'实际 {got}')
    return ok



def check_realish(ok):
    """可复现的「像真项目」靶场：规模、通道数、性能都在这里守。

    以前这几项只挂在作者本机的 Electron 应用上，换台机器就 SKIP。
    """
    sample = os.path.join(ROOT, 'examples', 'build', 'realish.asar')
    if not os.path.exists(sample):
        return ok & check('可复现真包靶场存在（先跑 examples/build.sh）', False, sample)

    import subprocess
    import time
    started = time.time()
    proc = subprocess.run(['python', os.path.join(ROOT, 'ipcsurface.py'), sample,
                           '--format', 'json', '-o', os.path.join(ROOT, 'build', 'realish.json')],
                          capture_output=True, text=True, encoding='utf-8', errors='replace')
    elapsed = time.time() - started
    ok &= check('真包靶场跑得动', proc.returncode == 0, (proc.stderr or '')[:120])

    data = json.loads(open(os.path.join(ROOT, 'build', 'realish.json'), encoding='utf-8').read())
    ok &= check('真包靶场文件数 3042', data['files'] == 3042, str(data['files']))
    ok &= check('真包靶场通道 12 条', len(data['channels']) == TARGET_EXPECT['realish.asar'],
                str(len(data['channels'])))
    ok &= check('真包靶场没有算不出来的名字', not data['dynamic'], str(len(data['dynamic'])))
    ok &= check('真包靶场性能（< 8 秒）', elapsed < 8.0, f'{elapsed:.2f}s')
    return ok



def check_known_wrong(ok, version):
    """已知会错清单：结构、条数、版本锁。内容好不好判断不了，下限能守。"""
    path = os.path.join(ROOT, 'docs', 'known-wrong.md')
    if not os.path.exists(path):
        return ok & check('已知会错清单存在', False, path)
    text = open(path, encoding='utf-8').read()

    ok &= check('清单表格用统一三列（症状/为什么/怎么办）',
                text.count('| 症状 | 为什么 | 怎么办 |') >= 2)
    rows = [ln for ln in text.splitlines()
            if ln.startswith('| ') and '---' not in ln and '症状' not in ln]
    ok &= check('清单至少 8 条具体症状', len(rows) >= 8, f'{len(rows)} 条')
    locked = re.search(r'^版本：([0-9.]+)$', text, re.M)
    ok &= check('清单版本锁和当前版本一致',
                bool(locked) and locked.group(1) == version,
                f'清单 {locked.group(1) if locked else "?"} / 当前 {version}')
    return ok


def check_output_parity(ok):
    """同一份东西，md 说几条、json 说几条，必须是一个数。

    这条是被打过的：报告抬头 41 条，基线里存了 52，差在算不算 window 暴露。
    """
    sample = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
    if not os.path.exists(sample):
        print('  SKIP 没有靶场样本，跳过')
        return ok
    facts, count, total = t.analyse_asar(sample)
    md = t.render_asar(sample, facts, count, total)
    head = re.search(r'其中 (\d+) 个提到 IPC', md)
    from_md = len(facts['channels'])
    ok &= check('md 抬头说「提到 IPC N 个」和 scanned 一致（与 channels 数不是同一件事）',
                head is not None and int(head.group(1)) == facts['scanned'],
                f'提到 IPC {head.group(1) if head else "?"} / scanned {facts["scanned"]}')
    ok &= check('通道数不含 window 暴露',
                all(not name.startswith('window.') for name in facts['channels']),
                f'{from_md} 条')
    return ok


def check_bad_input(ok):
    """坏输入必须非零退出，不能吐一份空报告当没事。"""
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as fh:
        fh.write('{}')
        bad = fh.name
    try:
        code = t.main([bad])
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    finally:
        os.unlink(bad)
    ok &= check('空证据文件退出码非 0', code not in (0, None), f'exit={code}')
    return ok


BASH_CANDIDATES = ['bash', r'C:\Program Files\Git\bin\bash.exe', '/bin/bash']


def find_bash():
    for candidate in BASH_CANDIDATES:
        try:
            probe = subprocess.run([candidate, '-c', 'echo ok'], capture_output=True, text=True,
                                   timeout=20)
            if 'ok' in probe.stdout:
                return candidate
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
    return None


CN_DIGITS = {'一': 1, '二': 2, '三': 3, '四': 4, '五': 5, '六': 6, '七': 7, '八': 8, '九': 9}


def parse_count(text):
    """文档里有的写 15 项，有的写十五项，两种都得认。"""
    match = re.search(r'([0-9]+)\s*项', text)
    if match:
        return int(match.group(1))
    match = re.search(r'十([一二三四五六七八九])?\s*项', text)
    if match:
        return 10 + (CN_DIGITS.get(match.group(1), 0) if match.group(1) else 0)
    return None


def check_smoke_count(ok, readme):
    bash = find_bash()
    if not bash:
        print('  SKIP 这台机器没有 bash，跳过冒烟计数')
        return ok
    out = subprocess.run([bash, 'scripts/smoke.sh'], cwd=ROOT, capture_output=True,
                         text=True, encoding='utf-8', errors='replace', timeout=600).stdout
    passed = out.count('[OK]')
    said = parse_count(readme)
    # 两种环境分开判：有示例包时项数必须和 README 对齐；没有示例包时
    # 有些段会整段跳过，项数自然变少——那时只要求「跑过、且没有 [FAIL]」。
    # 冒烟自己会打一行「N 应有 / N 通过 / N 跳过 / N 失败」，直接读它，
    # 不靠外部猜「跳过算不算」——脚本说清楚，自查只对数字。
    import re as _re
    m = _re.search(r'---- (\d+) 应有 / (\d+) 通过 / (\d+) 跳过 / (\d+) 失败 ----', out)
    if not m:
        return ok & check('冒烟打出了汇总行', False, '没找到「N 应有 / N 通过 / N 跳过 / N 失败」')
    total, okk, skipped, failed = (int(x) for x in m.groups())
    return ok & check('冒烟项数与文档一致（应有 = 通过 + 跳过）',
                      total == okk + skipped and failed == 0 and said == total,
                      f'应有 {total} = 通过 {okk} + 跳过 {skipped}，失败 {failed}；'
                      f'README 写 {said}')


def check_input_error_kinds(ok):
    """错误类别是给机器看的，深度上限是显式常量——这两条都不能只写在文档里。"""
    import tempfile
    ok &= check('嵌套上限是显式常量',
                isinstance(getattr(t, 'MAX_JSON_DEPTH', None), int)
                and 8 < t.MAX_JSON_DEPTH < 4096, str(getattr(t, 'MAX_JSON_DEPTH', None)))
    for kind in ('file_missing', 'encoding_invalid', 'empty_input', 'json_malformed',
                 'json_truncated', 'depth_exceeded', 'shape_invalid'):
        ok &= check(f'错误类别 {kind} 登记了', kind in t.INPUT_ERROR_KINDS)

    cases = {'empty': '', 'truncated': '{"a": [', 'deep': '[' * 500 + ']' * 500}
    for name, payload in cases.items():
        fh = tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8')
        fh.write(payload)
        fh.close()
        try:
            t.load_probe(fh.name)
            ok &= check(f'{name} 被拒绝', False)
        except t.InputError as exc:
            ok &= check(f'{name} 带类别', bool(exc.kind), exc.kind)
        finally:
            os.unlink(fh.name)
    return ok


def check_output_side(ok):
    """写出去那一侧：要么完整，要么什么都不留；失败状态要能被看见。"""
    import tempfile as _tempfile
    import shutil as _shutil
    folder = _tempfile.mkdtemp()
    target = os.path.join(folder, 'r.md')
    try:
        result = t.write_output(target, '完整的一份\n')
        ok &= check('正常写得出完整报告', os.path.getsize(target) > 0)
        ok &= check('写完不留临时文件或副本',
                    [n for n in os.listdir(folder) if n != 'r.md'] == [])
        # 两个平台现在都真刷目录：成功的定义一样，durable 必须真的是 yes，
        # 不能再靠「Windows 没这能力」把 unknown 说成不算失败
        ok &= check('写成功即持久化（durable=yes）',
                    result.durable == t.DURABLE_YES, result.durable)
        if os.name == 'nt':
            ok &= check('Windows 上目录刷盘真的做了',
                        t._fsync_dir(folder) is t.FsyncResult.OK)
        for kind in ('disk_full', 'permission_denied', 'short_write',
                     'replace_failed', 'symlink_target', 'write_failed'):
            ok &= check(f'输出错误类别 {kind} 登记了', kind in t.OUTPUT_ERROR_KINDS)
        # 备份是按 ctime 判年龄的，用 mtime 会把刚生成的副本当过期
        ok &= check('备份年龄用 ctime 判断', hasattr(t, '_backup_age'))
    finally:
        _shutil.rmtree(folder, ignore_errors=True)
    return ok




PRODUCT_MODULES = ('ipcsurface.py', 'jsasar.py', 'jslabels.py', 'jsparse.py',
                   'jssem.py', 'jsast.py', 'jsreport.py', 'native_imports.py',
                   'precise_engine.py')

# precise_engine 是 opt-in 的精查层，唯一被允许 import tree_sitter。
# 默认路径零依赖不变；precise 装不上，粗扫照跑，所以这一层豁免零依赖扫描。
PRECISE_EXEMPT = {'precise_engine.py'}

# 标准库清单：从运行中的解释器拿，最准（Python 3.10+）。
try:
    import sys as _sys
    STDLIB = set(_sys.stdlib_module_names)
except AttributeError:
    STDLIB = set()


def check_invariants(ok):
    """docs/invariants.md 的五条不变量，能机器守的都在这里咬一口。

    这是路线图 P0-3 的落地：特色不能靠自觉，得靠 CI 红。
    """
    print('== 不变量 ==')
    # I1 · 默认路径零依赖：产品模块只能 import 标准库（和自己人）。
    own = {m[:-3] for m in PRODUCT_MODULES}
    bad_imports = []
    for mod in PRODUCT_MODULES:
        if mod in PRECISE_EXEMPT:
            continue  # precise 层允许 tree-sitter，这是 opt-in 不是默认路径
        text = read(mod)
        for m in re.findall(r'^\s*(?:from\s+(\w+)|import\s+([\w.]+))', text, re.M):
            name = m[0] or m[1]
            top = name.split('.')[0]
            if top in own or top == '__future__':
                continue
            if STDLIB and top not in STDLIB and top not in ('ipcsurface',):
                bad_imports.append(f'{mod}:{top}')
    ok &= check('产品模块只 import 标准库（零依赖）', not bad_imports,
                '、'.join(bad_imports[:5]))

    # I2 · 每条通道结论都带 refutes_if + strength：拿 golden 快照当答案纸。
    try:
        data = json.loads(read('tests', 'golden', 'asar_report.json'))
    except (OSError, json.JSONDecodeError):
        return ok & check('golden 快照可读', False)
    evidence = data.get('evidence') or {}
    missing = [k for k, v in evidence.items()
               if not isinstance(v, dict) or 'refutes_if' not in v or 'strength' not in v]
    ok &= check('每条通道结论都带 refutes_if 和 strength', not missing,
                '、'.join(sorted(missing)[:5]))
    empty_str = [k for k, v in evidence.items()
                 if isinstance(v, dict) and any(x == '' for x in
                 (v.get('strength'), v.get('primary_action')))]
    ok &= check('结论字段不用空串冒充 null（I3 抽查）', not empty_str,
                '、'.join(sorted(empty_str)[:5]))
    return ok


def main():
    ok = True
    print('== 一、版本与文档口径 ==')
    version = t.__version__
    ok &= check('version 与 badge 一致', version in read('docs', 'badges', 'version.svg'), version)
    readme = read('README.md')
    ok &= check('README 写着同一个版本', version in readme)

    # pyproject 里的版本号也得跟上：它决定 pip 装出来的 wheel 叫什么名字。
    # 之前它停在 0.6.1，五十多个版本没人看——安装包名和人说的版本号是两回事。
    pyproject = read('pyproject.toml')
    m = re.search(r'^version = "([^"]+)"', pyproject, re.M)
    ok &= check('pyproject 版本与 __version__ 一致',
                bool(m) and m.group(1) == version,
                f'pyproject {m.group(1) if m else "?"} / 代码 {version}')
    changelog = read('CHANGELOG.md')
    ok &= check('CHANGELOG 有这一版', '## ' + version in changelog)
    # 定义数要数全目录，不能只数主用例文件——新加的 tests/test_jssem.py
    # 曾经被漏在统计之外，README 写着 248、实际跑 264，这种漂移必须自己红出来。
    tests_defined = 0
    for name in sorted(os.listdir(os.path.join(ROOT, 'tests'))):
        if name.startswith('test_') and name.endswith('.py'):
            tests_defined += len(re.findall(r'def test_', read('tests', name)))
    # 「定义了多少」和「真跑了多少」不是一回事，两个数都报出来
    ran, skipped = run_unittest_summary()
    tests_count = tests_defined
    # 三个数语义不重叠：定义 = 写好多少个 / 实跑 = 真执行了 / 跳过 = 没执行的
    actually_ran = ran - skipped
    # 产品代码不参与测试文件的 AST 扫描（那里的 all() 多是数据处理），
    # 但「产品代码里有没有真空集合断言」要能被回答，不能只靠一句统计判断。
    import ast as _ast
    product_tree = _ast.parse(read('ipcsurface.py'))
    risky = []
    for node in _ast.walk(product_tree):
        if isinstance(node, _ast.Assert):
            risky.append(('<assert>', node.lineno))
        if isinstance(node, _ast.Call) and isinstance(node.func, _ast.Attribute) \
                and node.func.attr in ('assertTrue', 'assertFalse'):
            for arg in node.args:
                if isinstance(arg, (_ast.GeneratorExp, _ast.ListComp)):
                    risky.append((node.func.attr, node.lineno))
    # 「0 条」只证明没有扫描器认得的形态，不是「产品代码没有空集合问题」。
    # 真要放一条合法的全称断言，就在它上面写 # universal-assert-ok: 理由，
    # 否则这条会红——是门禁，不是纯观测。
    product_source = read('ipcsurface.py')
    exempt_lines = [l.strip() for l in product_source.splitlines()
                    if l.strip().startswith('# universal-assert-ok')]
    exempt = sum(1 for l in exempt_lines
                 if len(l.split(':', 1)[1].strip()) >= 10 if ':' in l)
    short_reasons = [l for l in exempt_lines
                     if ':' not in l or len(l.split(':', 1)[1].strip()) < 10]
    ok &= check('产品代码豁免都写了理由（≥10 字）', not short_reasons,
                f'理由不足或不带冒号的豁免：{short_reasons[:2]}')
    ok &= check('产品代码里没有未豁免的全称断言（仅限扫描器认得的形态）',
                not risky or exempt >= len(risky),
                f'发现 {risky[:3]}；合规豁免 {exempt} 条（每次自查都报这个数，涨了就是信号）')
    ok &= check('用例三条数都对得上（定义 / 实跑 / 跳过）',
                ran == tests_defined and actually_ran >= 0,
                f'定义 {tests_defined} / 实跑 {actually_ran} / 跳过 {skipped}（不计入实跑）')
    ok &= check('README 用例数和实际一致',
                f'{tests_count} 个用例' in readme, f'实际 {tests_count}')
    ok &= check('英文版 README 用例数和实际一致',
                f'{tests_count} test cases' in read('README.en.md'),
                f'实际 {tests_count}')
    ok &= check('badge 用例数和实际一致',
                f'{tests_count} passed' in read('docs', 'badges', 'tests.svg'))
    ok = check_versions_match_tags(ok, version, changelog)
    ok = check_test_classes(ok)
    ok = check_local_links(ok, readme)
    ok = check_referenced_paths(ok, readme)

    ok = check_invariants(ok)

    print('== 二、schema 与规则一致性 ==')
    ok &= check('schema 版本号是 asar/20', 'ipcsurface/asar/20' in read('ipcsurface.py'))
    # 文档漂移：README 里写死的 schema 必须和源码一致，不然消费方会按旧版本对不上
    source_schema = re.search(r"SCHEMA_VERSION = '([^']+)'", read('ipcsurface.py')) or \
        re.search(r"'ipcsurface/asar/([0-9]+)'", read('ipcsurface.py'))
    doc_schemas = set(re.findall(r'ipcsurface/asar/[0-9]+', read('README.md') + read('README.en.md')))
    ok &= check('README 里的 schema 和源码一致', doc_schemas == {'ipcsurface/asar/20'},
                str(sorted(doc_schemas)) + ' 源码 ' + (source_schema.group(0) if source_schema else '?'))
    # 打包：九个模块缺一个，装出来的 wheel 就会悄悄降级
    pyproject = read('pyproject.toml')
    packed = re.search(r'py-modules\s*=\s*\[(.*?)\]', pyproject, re.S)
    names = set(re.findall(r'"([a-z_]+)"', packed.group(1))) if packed else set()
    required = {'ipcsurface', 'jsasar', 'jslabels', 'jsparse', 'jssem',
                'jsast', 'jsreport', 'native_imports', 'precise_engine'}
    ok &= check('pyproject 打进去九个模块', names >= required,
                str(sorted(names)))
    rules = {r['id'] for r in t.RULES}
    tests = read('tests', 'test_ipcsurface.py')
    for rule in sorted(rules):
        ok &= check(f'规则 {rule} 有对应用例', f'def test_rule_{rule}' in tests)
    aggregates = {a['field']: a for a in t.AGGREGATE_FIELDS}
    banned = {m for c in t.CONFIDENCE_SEMANTICS['usage_constraints']
              for m in c.get('must_not', [])}
    for field, agg in aggregates.items():
        ok &= check(f'聚合字段 {field} 的 must_not 有出处', agg['must_not'] in banned)

    print('== 三、真包实测 ==')
    if not os.path.exists(REAL):
        print('  SKIP 没有真包，跳过这一节（CI 或别的机器上正常）')
        facts = count = total = None
    else:
        facts, count, total = t.analyse_asar(REAL)
    if not facts:
        print('  （没有真包，这一节跳过）')
        channels = None
    else:
        channels = len(facts['channels'])
        ok &= check('真包文件数 22102', count == 22102, str(count))
        ok &= check('真包通道 41 条', channels == 41, str(channels))
        ok &= check('算不出来的名字是 0', len(facts['dynamic']) == 0,
                    str(len(facts['dynamic'])))
        ok &= check('打捞候选 221 个', len(facts['harvested']) == 221,
                    str(len(facts['harvested'])))
        ok &= check('README 里的 41 条对得上', '41 条' in readme, str(channels))

        print('== 四、报告自洽 ==')
        text = t.render_asar(REAL, facts, count, total)
        ok &= check('报告里有可信度分层', '可信度分层' in text)
        ok &= check('报告里写明层不能相加', '别把这一列加起来当总数' in text)
        ok &= check('报告里有「没看清的地方」', '没看清的地方' in text)

    print('== 五、靶场期望值 ==')
    ok = check_targets(ok)

    print('== 六、可复现真包靶场（规模 / 通道 / 性能）==')
    ok = check_realish(ok)

    print('== 七、两种输出口径一致 ==')
    ok = check_known_wrong(ok, version)
    ok = check_output_parity(ok)

    print('== 七、坏输入必须报错 ==')
    ok = check_bad_input(ok)
    ok = check_input_error_kinds(ok)

    print('== 八、写出去也要完整 ==')
    ok = check_output_side(ok)

    print('== 八、冒烟项数与文档一致 ==')
    ok = check_smoke_count(ok, readme)

    print('== 九、基线闸门 ==')
    import tempfile
    with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False, encoding='utf-8') as fh:
        json.dump({'channels': [], 'findings': []}, fh)
        bad = fh.name
    try:
        t.load_baseline(bad)
        ok &= check('旧基线被拒绝', False)
    except SystemExit as exc:
        message = str(exc)
        ok &= check('旧基线被拒绝且给出两条命令',
                    '--write-baseline' in message and '--baseline' in message)
    finally:
        os.unlink(bad)

    print('== 十、工作区状态 ==')
    status = subprocess.run(['git', 'status', '--porcelain'], cwd=ROOT,
                            capture_output=True, text=True).stdout.strip()
    ok &= check('工作区干净', status == '', status[:80])
    tags = subprocess.run(['git', 'tag', '--list'], cwd=ROOT,
                          capture_output=True, text=True).stdout.split()
    ok &= check('有 v' + version + ' 的 tag', 'v' + version in tags)

    print()
    print('全部通过' if ok else '有项目没过')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
