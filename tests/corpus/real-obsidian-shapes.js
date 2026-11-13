// 从 obsidian.asar 的 app.js（3.9 MB，压缩成一整行）里原样抄下来的三段。
// 不是为了「像」，是为了让用例跑在真包的真实形状上：
// 少一个逗号、写法换个顺序，判断结果就该不一样。
// 唯一的改动是换行和缩进，token 序列没动。

l.ipcMain.on("set-icon", (o, i, c) => {
  C.icon && m.rmSync(F.join(v, C.icon), { force: !0 }),
    i && c ? m.writeFileSync(F.join(v, i), c) : (i = null),
    (C.icon || "") !== (i || "") && (i ? C.icon = i : delete C.icon, _()),
    (o.returnValue = null);
});

l.ipcMain.on("adblock-frequency", (o, i) => {
  typeof i == "number" && (C.adblockFrequency = i, _(), we()),
    (o.returnValue = C.adblockFrequency || gt);
});

l.ipcMain.on("frame", (o, i) => {
  typeof i == "string" && (C.frame = i, i || delete C.frame, _()),
    (o.returnValue = C.frame);
});
