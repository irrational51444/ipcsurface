"""自查：把这一晚上堆起来的东西逐项核一遍，看有没有名不副实的地方。"""
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, r'C:\Users\irrational\Desktop\rea-lab')
import ipcsurface as t

REAL = r'C:\Users\irrational\AppData\Local\Programs\DeepSeek Harness\resources\app.asar'
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    return open(os.path.join(ROOT, *parts), encoding='utf-8').read()


def check(label, ok, detail=''):
    print(('  OK   ' if ok else '  FAIL ') + label + (('  ' + detail) if detail else ''))
    return ok


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


def main():
    ok = True
    print('== 一、版本与文档口径 ==')
    version = t.__version__
    ok &= check('version 与 badge 一致', version in read('docs', 'badges', 'version.svg'), version)
    readme = read('README.md')
    ok &= check('README 写着同一个版本', version in readme)
    changelog = read('CHANGELOG.md')
    ok &= check('CHANGELOG 有这一版', '## ' + version in changelog)
    tests_count = len(re.findall(r'def test_', read('tests', 'test_ipcsurface.py')))
    ok &= check('README 用例数和实际一致',
                f'{tests_count} 个用例' in readme, f'实际 {tests_count}')
    ok &= check('badge 用例数和实际一致',
                f'{tests_count} passed' in read('docs', 'badges', 'tests.svg'))
    ok = check_versions_match_tags(ok, version, changelog)
    ok = check_test_classes(ok)
    ok = check_local_links(ok, readme)
    ok = check_referenced_paths(ok, readme)

    print('== 二、schema 与规则一致性 ==')
    ok &= check('schema 版本号是 asar/10', 'ipcsurface/asar/10' in read('ipcsurface.py'))
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

    print('== 五、基线闸门 ==')
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

    print('== 六、工作区状态 ==')
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
