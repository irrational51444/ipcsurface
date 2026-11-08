"""发布前的守卫：标签指向的提交必须 CI 绿。

用法：
    python scripts/check_release_tag.py v0.65.4

需要环境变量 GITHUB_TOKEN（或用 git credential 里存的）。没有网络/没凭据时
会明确说「无法确认」，退出码 2，不假装通过。
"""
import json
import os
import subprocess
import sys
import urllib.request

REPO = 'irrational51444/ipcsurface'


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


def main():
    if len(sys.argv) < 2:
        print('用法：python scripts/check_release_tag.py <tag>')
        return 1
    tag = sys.argv[1]

    sha = subprocess.run(['git', 'rev-list', '-n', '1', tag],
                         capture_output=True, text=True).stdout.strip()
    if not sha:
        print(f'FAILED: 本地没有标签 {tag}')
        return 1

    tok = token()
    if not tok:
        print(f'无法确认：没有凭据，无法查询 {sha} 的 CI 结果（标签本身存在）')
        return 2

    url = f'https://api.github.com/repos/{REPO}/commits/{sha}/check-runs'
    req = urllib.request.Request(url, headers={
        'Authorization': f'token {tok}',
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'check-release-tag'})
    try:
        data = json.load(urllib.request.urlopen(req, timeout=30))
    except Exception as exc:
        print(f'无法确认：查询 CI 失败（{exc}）')
        return 2

    runs = data.get('check_runs', [])
    if not runs:
        print(f'无法确认：{tag} 指向的 {sha[:7]} 没有任何 CI 结果')
        return 2

    bad = [r['name'] for r in runs if r.get('conclusion') not in ('success', 'skipped')]
    if bad:
        print(f'FAILED: {tag} 指向 {sha[:7]}，但这些检查不是绿：{", ".join(bad)}')
        return 1

    print(f'DONE: {tag} 指向 {sha[:7]}，{len(runs)} 个检查全绿')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
