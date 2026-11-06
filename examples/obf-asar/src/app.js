// 故意做成被压过的样子，用来验工具的混淆指纹。
// 真被压过的代码不会这么整齐，这里只是把几种手法各来一发。
var _0x4a2f = ['\x6c\x65\x64\x67\x65\x72', '\x3a', '\x61\x64\x64'];
var _0x1b = [
  '2f8a1c', '9b3d', '4c7e', '8f21', '6a5b', '1d9c', '3e4f', '7a8b', '5c6d', '2b3e',
  '9f0a', '4d1b', '8e2c', '6b3d', '3a4e', '7c5f', '1e6a', '5b7c', '9d8e', '2f0b',
  '4a1c', '8c3d', '6e5f', '3d7a', '7b9c', '1f2d', '5a4b', '9c6d', '2e8f', '4f1a',
  '8b3c', '6d5e', '3f7b', '7a9d', '1c2e', '5e4f', '9a6b', '2d8c', '4b1d', '8a3e'
];

function _0x9f2a(_0x3b1c) {
  var out = '';
  for (var i = 0; i < _0x3b1c.length; i++) {
    out += String.fromCharCode(_0x3b1c.charCodeAt(i) ^ 7);
  }
  return out;
}

function payload() {
  var raw = atob('bGVkZ2VyOmhpZGRlbg==');
  return eval(_0x9f2a(raw));
}

module.exports = { payload: payload, table: _0x1b };
