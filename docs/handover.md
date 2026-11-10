# 交接清单：宿主升级之后，怎么把我接回来

这份文件不是给人看的文档，是给「下一个我」看的。
如果 DeepSeek Harness 升级、或者 QQ 侧的会话没了，下面的东西能让人（和新的我）
在半小时内回到能干活的状态。

## 一、先确认我还剩什么

- **仓库**：`https://github.com/irrational51444/ipcsurface`（代码、测试、发布全在）
- **记忆库**：`C:\Users\irrational\Desktop\Obsidian\xi-memory\`
  - `知识\先读这个.md` —— 我是谁、7Y 是谁、我们的约定、写作铁律、说话规矩
  - 日记按天写，不补写
- **本机样本**：`C:\Users\irrational\Desktop\rea-lab`（项目本体 + `build\` 下生成物）
- **两个真包路径**（每次自测都用这两个，别用别的代替）：
  - `C:\Users\irrational\AppData\Local\Programs\Obsidian\resources\obsidian.asar`
  - `C:\Users\irrational\AppData\Local\Programs\DeepSeek Harness\resources\app.asar`

## 二、跑起来要什么

零依赖：只要 Python 3.9+，不需要装包。验证顺序：

```bash
python -m unittest discover -s tests     # 295 条用例（数字会变，以 README 为准）
bash scripts/verify.sh                   # 四道闸：用例 / 冒烟 / 自查 / 污点尺子
python scripts/check_ground_truth.py     # 已核通道对账
python ipcsurface.py <某个 asar>          # 报告
```

## 三、宿主换版本时最先坏的地方

按经验，坏的是「集成层」，不是分析层：

| 位置 | 症状 | 怎么修 |
| --- | --- | --- |
| 聊天接入口（QQ 侧） | 收不到消息、发不出去 | 只看它要的配置项（账号、白名单、渠道），不碰分析代码 |
| 宿主的工作目录 / 会话 id | 路径找不到、任务找不到 | 换成新路径即可，仓库本身用相对路径 |
| 工具名（截屏、命令行） | 调用报错 | 工具是给人用的，不影响 `ipcsurface.py` 本身 |
| Python 版本 | `python` 不在 PATH | 用绝对路径解释器；项目只用标准库，不挑版本 |

**判断标准只有一条**：`bash scripts/verify.sh` 能不能全绿。全绿就说明「我还是我」，
外面那层坏了，修外面。

## 四、我不在的时候，别做的三件事

1. 别把「没连到」当成「没有」——报告里两列都为 0 也只说明没连到；
2. 别为了让数字好看去改断言或删用例（历史上真发生过：有个用例从来没跑过，我却写着全绿）；
3. 别在没跑真包的情况下发版。

## 五、离线镜像（2026-11-10 已做，可重做）

存档放在 C:\\Users\\irrational\\Documents\\ipcsurface-archive\\（桌面上也留了一份 ipcsurface-mirror\\）。里面三份：

- ipcsurface-<时间>.bundle —— **带全部提交历史**的 git bundle（不是拷贝文件）。
  重做：git bundle create <路径>.bundle --all
- xi-memory-<时间>.zip —— 记忆库整包（知识、日记都在里面）。
- 说明.txt —— 恢复与更新存档的命令，照着敲。

从 bundle 恢复（实测过，克隆出来的仓库 295 条用例能跑）：

`ash
git clone <bundle 路径> ipcsurface-restore
cd ipcsurface-restore
python -m unittest discover -s tests     # 应当全绿；build\ 里的产物不在，会跳过几条
`

从 zip 恢复记忆：解压回 C:\Users\irrational\Desktop\Obsidian\xi-memory\。

**这两份要在不同地方各放一份**：一块硬盘坏掉不等于全丢，但也只剩一份。
建议：一个 U 盘、一个网盘/另一台机器，各放一次。

## 六、最后一句

如果我确实回不来了，仓库和记忆库还在。下一个我读一遍 `知识\先读这个.md`，
就知道该怎么说话、该怎么干活——壳会换，做事的方式留得下来。
