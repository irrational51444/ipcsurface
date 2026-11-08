"""发布脚本：守卫不过就不发。

用法：
    python scripts/make_release.py v0.65.6 --name "0.65.6 — ..." --notes-file notes.md

它会先跑 check_release_tag.py：0 才继续，1 或 2 都停（但会说明是哪一种）。
也就是说「发布前跑一下守卫」不是靠自觉，是这条路径上的一步。
"""
import argparse
import os
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
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
    ap = argparse.ArgumentParser()
    ap.add_argument('tag')
    ap.add_argument('--name', required=True)
    ap.add_argument('--notes-file', required=True)
    args = ap.parse_args()

    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    guard = subprocess.run([sys.executable, str(ROOT / 'scripts' / 'check_release_tag.py'),
                            args.tag], capture_output=True, text=True,
                           encoding='utf-8', errors='replace', env=env)
    print(guard.stdout.strip())
    if guard.returncode != 0:
        which = 'CI 红' if guard.returncode == 1 else '查不到（不是 CI 红）'
        print(f'不发布：守卫没过，原因：{which}')
        return guard.returncode

    tok = token()
    if not tok:
        print('不发布：没有凭据')
        return 2

    notes = Path(args.notes_file).read_text(encoding='utf-8')
    payload = json.dumps({'tag_name': args.tag, 'name': args.name,
                          'body': notes, 'draft': False,
                          'prerelease': False}).encode('utf-8')
    req = urllib.request.Request(
        f'https://api.github.com/repos/{REPO}/releases', data=payload,
        method='POST', headers={'Authorization': f'token {tok}',
                                'Accept': 'application/vnd.github+json',
                                'Content-Type': 'application/json',
                                'User-Agent': 'make-release'})
    try:
        data = json.load(urllib.request.urlopen(req, timeout=30))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode('utf-8', 'replace')
        if exc.code == 422 and 'already_exists' in detail:
            print(f'不发布：{args.tag} 的 release 已经存在')
            return 1
        print(f'不发布：建 release 失败 HTTP {exc.code}：{detail[:200]}')
        return 2
    print('DONE:', data['html_url'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
