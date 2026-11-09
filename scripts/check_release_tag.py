"""发布前的守卫：标签指向的提交必须 CI 绿。

用法：
    python scripts/check_release_tag.py v0.65.6

退出码（不是两态，下游别按「非零即失败」处理）：
    0  标签指向的提交，CI 全绿
    1  CI 有红检查 —— 该修代码或换提交
    2  查询失败（没凭据 / 没网络 / 非 200 / 查不到 checks）—— 重试或查凭据

为什么 1 和 2 要分开：这两种情况下发布者该做的事完全不同。
脚本本身被测（tests/test_ipcsurface.py::ReleaseGuardTests），三条用例分别对应三个分支。
"""
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

REPO = 'irrational51444/ipcsurface'

EXIT_OK = 0
EXIT_RED = 1
EXIT_UNKNOWN = 2


def token():
    tok = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    if tok:
        return tok
    try:
        out = subprocess.run(['git', 'credential', 'fill'],
                             input='protocol=https\nhost=github.com\n\n',
                             capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return ''
    for line in out.splitlines():
        if line.startswith('password='):
            return line.split('=', 1)[1]
    return ''


def evaluate(runs):
    """纯函数：给一串 check_run，判断该退什么码。

    区分三件事：
    - 没有任何 check：查不到结果（2），不是红
    - 有 check 还没跑完（status 不是 completed）：查不到结果（2），不是红
    - 有 check 跑完了但结论不是成功/跳过：红（1）
    - 全部成功或跳过：绿（0）

    第三和第四条以前会混：`conclusion` 在跑完前是 null，被当成「不是成功」
    就报红了。刚推完标签去查，必然撞上这个——那不是代码红，是还没跑完。
    """
    if not runs:
        return EXIT_UNKNOWN, '查不到这个提交的 CI 结果（可能还没跑；不是 CI 红）'
    pending = [r.get('name', '?') for r in runs
               if r.get('status', 'completed') != 'completed']
    if pending:
        return EXIT_UNKNOWN, ('这些检查还没跑完：' + '、'.join(pending)
                              + '（等它结束再查一次，不是 CI 红）')
    bad = [r.get('name', '?') for r in runs
           if r.get('conclusion') not in ('success', 'skipped')]
    if bad:
        return EXIT_RED, '这些检查不是绿：' + '、'.join(bad)
    return EXIT_OK, f'{len(runs)} 个检查全绿'


def fetch_runs(sha, tok, repo=REPO, timeout=30):
    """拿 check runs。任何「没拿到」都抛异常，由调用方归为 2。"""
    url = f'https://api.github.com/repos/{repo}/commits/{sha}/check-runs'
    req = urllib.request.Request(url, headers={
        'Authorization': f'token {tok}',
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'check-release-tag'})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp).get('check_runs', [])


def check_tag(tag, tok=None, fetcher=None):
    sha = subprocess.run(['git', 'rev-list', '-n', '1', tag],
                         capture_output=True, text=True).stdout.strip()
    if not sha:
        return EXIT_UNKNOWN, f'本地没有标签 {tag}'

    tok = tok if tok is not None else token()
    if not tok:
        return EXIT_UNKNOWN, f'没有凭据，无法查询 {sha[:7]} 的 CI 结果'

    fetcher = fetcher or fetch_runs
    try:
        runs = fetcher(sha, tok)
    except urllib.error.HTTPError as exc:
        return EXIT_UNKNOWN, f'查询失败：HTTP {exc.code}（不是 CI 红）'
    except Exception as exc:
        return EXIT_UNKNOWN, f'查询失败：{type(exc).__name__}（不是 CI 红）'

    code, why = evaluate(runs)
    return code, f'{tag} 指向 {sha[:7]}，{why}'


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print('用法：python scripts/check_release_tag.py <tag>')
        return 1
    code, message = check_tag(argv[0])
    print(('DONE: ' if code == EXIT_OK else
           'FAILED: ' if code == EXIT_RED else 'UNKNOWN: ') + message)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
