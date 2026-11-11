# 和 Electronegativity 的定位区别

有人会问：这跟 [Electronegativity](https://github.com/doyensec/electronegativity)
是不是一回事。不是，各有各的活。

| | Electronegativity | ipcsurface |
| --- | --- | --- |
| 回答什么问题 | 「代码里有没有已知的**漏洞模式**」（`shell.openExternal` 拼了不受信 url、`nodeIntegration` 开着、`webSecurity` 关着……） | 「这个应用**能碰到哪些能力**，以及每条结论**能信多少**」 |
| 产出 | 一份带严重级的 findings 清单 | 能力面清单 + 每条通道的证据 / 强度 / 反证（refutes_if） |
| 姿态 | 找洞（opinionated，给 severity） | 摆证据（拒绝下结论，不评 severity） |
| 输入 | 解包后的目录 | .asar / Evidence JSON / PE，零依赖直接读 |

一句话：**Electronegativity 做漏洞模式，ipcsurface 做能力面 + 证据**。

两者可以配合：ipcsurface 先把「这个应用碰得到哪些危险 API」摊成一张能复算的图，
Electronegativity 再去那些真正碰得到的地方找具体漏洞模式。前者是地图，后者是
在地图上标雷点。缺地图，雷点标得再准也只是散点。

（这条定位也写进了路线图 P2-10，作为「外部可信度」的一部分。）
