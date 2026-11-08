"""发布脚本：守卫不过就不发。

    python scripts/make_release.py v0.65.7 --name "..." --notes-file notes.md

退出码（嵌套语义写清楚，别让下游把两种 2 混起来）：
    0  发布成功
    1  守卫红（该修代码/换提交），或这个 tag 的 release 已经存在
    2  守卫查不到（没凭据/没网络/非 200）——不是 CI 红
    3  脚本自己出错（建 release 时网络或 API 失败）

也就是说：2 永远是「没查清」，3 才是「脚本坏了」。这两个以前都笼统归到非零里。
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = 'irrational51444/ipcsurface'

EXIT_OK = 0
EXIT_GUARD_RED = 1
EXIT_GUARD_UNKNOWN = 2
EXIT_SCRIPT_ERROR = 3


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


def run_guard(tag):
    """调守卫，返回 (code, 输出)。0/1/2 原样透传。"""
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    proc = subprocess.run(
        [sys.executable, str(ROOT / 'scripts' / 'check_release_tag.py'), tag],
        capture_output=True, text=True, encoding='utf-8', errors='replace', env=env)
    return proc.returncode, (proc.stdout or '').strip()


def post_release(tag, name, notes, tok, repo=REPO):
    """建 release。异常交给调用方归到 3。"""
    payload = json.dumps({'tag_name': tag, 'name': name, 'body': notes,
                          'draft': False, 'prerelease': False}).encode('utf-8')
    req = urllib.request.Request(
        f'https://api.github.com/repos/{repo}/releases', data=payload,
        method='POST', headers={
            'Authorization': f'token {tok}',
            'Accept': 'application/vnd.github+json',
            'Content-Type': 'application/json',
            'User-Agent': 'make-release'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def publish(tag, name, notes, guard=None, poster=None, tok=None):
    """可测的主逻辑：守卫 → 发布。返回退出码与一行说明。"""
    guard = guard or run_guard
    code, output = guard(tag)
    if code == EXIT_GUARD_RED:
        return EXIT_GUARD_RED, f'{output}\n不发布：守卫没过，原因：CI 红'
    if code != EXIT_OK:
        return EXIT_GUARD_UNKNOWN, f'{output}\n不发布：守卫没过，原因：查不到（不是 CI 红）'

    tok = tok if tok is not None else token()
    if not tok:
        return EXIT_GUARD_UNKNOWN, f'{output}\n不发布：没有凭据'

    poster = poster or post_release
    try:
        data = poster(tag, name, notes, tok)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode('utf-8', 'replace')
        if exc.code == 422 and 'already_exists' in detail:
            return EXIT_GUARD_RED, f'{output}\n不发布：{tag} 的 release 已经存在'
        return EXIT_SCRIPT_ERROR, f'{output}\n发布失败：HTTP {exc.code}：{detail[:200]}'
    except Exception as exc:
        return EXIT_SCRIPT_ERROR, f'{output}\n发布失败：{type(exc).__name__}: {exc}'

    return EXIT_OK, f'{output}\nDONE: {data.get("html_url", "?")}'


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('tag')
    ap.add_argument('--name', required=True)
    ap.add_argument('--notes-file', required=True)
    args = ap.parse_args(argv)

    notes = Path(args.notes_file).read_text(encoding='utf-8')
    code, message = publish(args.tag, args.name, notes)
    print(message)
    return code


if __name__ == '__main__':
    raise SystemExit(main())
