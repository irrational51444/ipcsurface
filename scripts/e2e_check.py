"""端到端：装好的命令行 → 真靶场 → 报告，三条口径一起验。

跑的路径和用户一样：调 `ipcsurface` 可执行文件，不看内部函数。
验四件事：
  1. 沙盒退出码 0，json 能解析，schema 对得上
  2. md 和 json 说的通道数一致
  3. 有问题的包 `--fail-on high` 退 2
  4. 同一个包写两次，内容一样（确定性）
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.path.join(ROOT, 'examples', 'build')
REALISH = os.path.join(BUILD, 'realish.asar')
OBF = os.path.join(BUILD, 'obf-asar.asar')
SCHEMA = 'ipcsurface/asar/11'

problems = []
COMMAND = (['ipcsurface'], '')


def check(name, condition, detail=''):
    print(('  OK   ' if condition else '  FAIL ') + name + (f'  {detail}' if detail else ''))
    if not condition:
        problems.append(name)


def repo_version():
    import re
    text = open(os.path.join(ROOT, 'ipcsurface.py'), encoding='utf-8').read()
    return re.search(r"__version__ = '([^']+)'", text).group(1)


def pick_command():
    """优先用装好的命令；如果本机装的是旧版，就退回仓库里的那份并说明。

    CI 上两者应该一致；本机常有旧装，不能拿旧版的结果冒充端到端。
    """
    want = repo_version()
    try:
        got = subprocess.run(['ipcsurface', '--version'], capture_output=True, text=True,
                             encoding='utf-8', errors='replace').stdout.strip()
    except FileNotFoundError:
        got = ''
    if want and want in got:
        return ['ipcsurface'], f'用装好的命令（{got}）'
    return ([sys.executable, os.path.join(ROOT, 'ipcsurface.py')],
            f'本机装的是「{got or "无"}」，不是 {want}，改用仓库文件')


def run(args):
    cmd, _why = COMMAND
    return subprocess.run(cmd + args, capture_output=True, text=True,
                          encoding='utf-8', errors='replace')


def main():
    for path in (REALISH, OBF):
        if not os.path.exists(path):
            print(f'缺靶场 {path}，先跑 examples/build.sh')
            return 1

    global COMMAND
    COMMAND = pick_command()
    print('  ' + COMMAND[1])

    tmp = tempfile.mkdtemp()
    json_path = os.path.join(tmp, 'realish.json')
    md_path = os.path.join(tmp, 'realish.md')

    proc = run([REALISH, '--format', 'json', '-o', json_path])
    check('装好的命令能出 json', proc.returncode == 0, (proc.stderr or '')[:120])
    data = json.loads(open(json_path, encoding='utf-8').read())
    check('schema 对得上', data['schema'] == SCHEMA, data['schema'])
    check('通道 12 条', len(data['channels']) == 12, str(len(data['channels'])))
    check('文件数 3042', data['files'] == 3042, str(data['files']))

    proc = run([REALISH, '-o', md_path])
    check('装好的命令能出 md', proc.returncode == 0)
    text = open(md_path, encoding='utf-8').read()
    check('md 与 json 通道数一致', f'{len(data["channels"])} 条' in text,
          f'json {len(data["channels"])}')

    proc = run([OBF, '--fail-on', 'high', '-o', os.path.join(tmp, 'obf.md')])
    check('有问题的包退 2', proc.returncode == 2, str(proc.returncode))

    again = os.path.join(tmp, 'realish-2.json')
    run([REALISH, '--format', 'json', '-o', again])
    a = json.loads(open(json_path, encoding='utf-8').read())
    b = json.loads(open(again, encoding='utf-8').read())
    a.pop('generated_at', None)
    b.pop('generated_at', None)
    check('同一份输入两次跑结果一致', a == b)

    # 人工标注的 ground truth：把「我觉得准」变成召回/精确率
    gt = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'ground_truth_check.py')],
                        capture_output=True, text=True, encoding='utf-8', errors='replace')
    print(gt.stdout.strip()[-600:])
    check('ground truth 比对通过', gt.returncode == 0)

    print()
    if problems:
        print('没过的项：' + '、'.join(problems))
        return 1
    print('端到端全绿')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
