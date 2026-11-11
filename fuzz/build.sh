#!/bin/bash -eu
# OSS-Fuzz 的 build.sh：在 OSS-Fuzz 的 Linux 环境里，把 atheris + 项目源码
# 拼成可 fuzz 的二进制。oss-fuzz 仓库的 infra 会调用它。
# 参考：https://google.github.io/oss-fuzz/getting-started/new-project-guide/python-lang/

cd "$SRC"

# 项目零依赖，直接把源码目录并进 Python 路径即可。
pip3 install atheris

# 把 fuzz target 编译成一个 fuzz 二进制（atheris 用 py-afl/ libFuzzer 驱动）。
for target in atheris_fuzz; do
  atheris_prepare "$OUT"/$target.py "$SRC"/fuzz/$target.py \
    --python-path "$SRC" || true
done

# 兜底：atheris_prepare 不存在（版本差异）时，直接把源文件拷过去，
# 让 OSS-Fuzz 用默认的 python harness 跑。
cp "$SRC"/fuzz/atheris_fuzz.py "$OUT"/atheris_fuzz.py
