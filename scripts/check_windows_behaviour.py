"""Windows 上那些「和别人不一样」的行为，得有人在 Windows 上真的断言一遍。

这个脚本只在 Windows 上有意义；别的平台直接跳过并退出 0。
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ipcsurface as t  # noqa: E402

problems = []


def check(name, condition, detail=''):
    print(('  OK   ' if condition else '  FAIL ') + name + (f'  {detail}' if detail else ''))
    if not condition:
        problems.append(name)


if os.name != 'nt':
    print('不是 Windows，脚本跳过')
    raise SystemExit(0)

workdir = tempfile.mkdtemp()
target = os.path.join(workdir, 'report.md')

# 1) 目录 fsync 现在真的走 FlushFileBuffers：成功就该报 OK / durable=yes，
#    不能再拿「这套系统没有这个能力」当挡箭牌
fsync_state = t._fsync_dir(workdir)
check('目录 fsync 报 OK', fsync_state is t.FsyncResult.OK, repr(fsync_state))
result = t.write_output(target, 'x\n')
check('durable 是 yes', result.durable == t.DURABLE_YES, result.durable)
# 刷一个不存在的目录：有能力但没刷成，必须是 FAILED，不能退化成 UNSUPPORTED
missing = os.path.join(workdir, 'no-such-dir')
check('不存在的目录报 FAILED', t._fsync_dir(missing) is t.FsyncResult.FAILED)

# 2) 符号链接路径：建不了链接时跳过，能建就必须拒绝写
link = os.path.join(workdir, 'link.md')
try:
    os.symlink(target, link)
    made = True
except (OSError, NotImplementedError):
    made = False
if made:
    try:
        t.write_output(link, 'y\n')
        check('符号链接被拒绝', False, '居然写成功了')
    except t.OutputError as exc:
        check('符号链接被拒绝', exc.kind == 'symlink_target', exc.kind)
else:
    print('  SKIP 建不了符号链接（没有特权），拒绝路径未覆盖')

# 3) 替换被占用：用别的文件句柄占住 target 再换
occupied = os.path.join(workdir, 'busy.md')
with open(occupied, 'w', encoding='utf-8') as fh:
    fh.write('old\n')
try:
    handle = open(occupied, 'rb')
    try:
        t.write_output(occupied, 'new\n')
        print('  SKIP 这套文件系统不锁占用，替换成功（不算失败）')
    finally:
        handle.close()
except t.OutputError as exc:
    check('被占用时报 replace_failed', exc.kind == 'replace_failed', exc.kind)

# 4) 长路径：接近 260 字符的目录还能写出来
deep = os.path.join(workdir, *(['d' * 20] * 10))
long_path = os.path.join(deep, 'r.md')
try:
    t.write_output(long_path, 'deep\n')
    check('长路径写得出来', os.path.exists(t._win_long(long_path)),
          f'{len(os.path.abspath(long_path))} 字符')
except t.OutputError as exc:
    check('长路径写得出来', False, f'{exc.kind}: {exc}')

print()
if problems:
    print('没过的项：' + '、'.join(problems))
    raise SystemExit(1)
print('Windows 专属行为全部符合预期')
