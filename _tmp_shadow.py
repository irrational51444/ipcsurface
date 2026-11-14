import time

import ipcsurface as m
import precise_engine as p

PACKAGES = [
    (r'C:\Users\irrational\AppData\Local\Programs\Obsidian\resources\obsidian.asar', 'obsidian'),
    (r'C:\Users\irrational\AppData\Local\Programs\DeepSeek Harness\resources\app.asar', 'dsh'),
    (r'C:\Program Files\bilibili\resources\app.asar', 'bilibili'),
    (r'C:\Program Files (x86)\ACLOS\Launcher\resources\app.asar', 'aclos'),
]

for path, label in PACKAGES:
    header, files = m.read_asar(path)
    facts = m.scan_asar(files)
    coarse = {c.get('name') if isinstance(c, dict) else c
              for c in facts.get('channels') or []}
    t = time.monotonic()
    precise = p.analyse_asar_precise(path)
    dt = time.monotonic() - t
    only_c = sorted(coarse - set(precise))
    only_p = sorted(set(precise) - coarse)
    print('%-9s coarse=%-3d precise=%-3d only_coarse=%-3d only_precise=%-3d %.1fs'
          % (label, len(coarse), len(precise), len(only_c), len(only_p), dt),
          flush=True)
    if only_c:
        print('   coarse-only:', only_c[:5])
    if only_p:
        print('   precise-only:', only_p[:5])
