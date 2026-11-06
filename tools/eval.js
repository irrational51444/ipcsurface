#!/usr/bin/env node
/**
 * 求值器：把一小段代码丢进沙箱算个值出来。
 *
 * 用来干什么：混淆里那些自己算自己的名字——
 *   function _0x9f2a(s){ ... String.fromCharCode(s.charCodeAt(i) ^ 7) ... }
 *   ipcMain.handle(_0x9f2a('鄏鄐'), ...)
 * 静态分析到这儿就断，因为它不执行代码。这个脚本就是那一步的执行。
 *
 * 边界：
 *   - 只跑「一段函数定义 + 一个调用」，不跑整包
 *   - vm 沙箱，2 秒超时，不给 require、不给 process、不给网络
 *   - 输入从 stdin 读，输出 JSON
 *
 * 用法：
 *   echo "function f(){return 1}; f()" | node eval.js
 */
const vm = require('vm');

const TIMEOUT_MS = 2000;

function readStdin() {
  return new Promise((resolve, reject) => {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (buf += chunk));
    process.stdin.on('end', () => resolve(buf));
    process.stdin.on('error', reject);
  });
}

(async () => {
  const code = await readStdin();
  if (!code.trim()) {
    console.log(JSON.stringify({ ok: false, error: '没有输入' }));
    return;
  }

  // 沙箱里只给最基础的东西。别的一概不给。
  const sandbox = Object.create(null);
  sandbox.String = String;
  sandbox.Number = Number;
  sandbox.Array = Array;
  sandbox.JSON = JSON;
  sandbox.Math = Math;

  try {
    const context = vm.createContext(sandbox, {
      codeGeneration: { strings: false, wasm: false }, // 不许 eval / new Function
    });
    const value = vm.runInContext(code, context, {
      timeout: TIMEOUT_MS,
      displayErrors: false,
    });
    console.log(JSON.stringify({ ok: true, value: typeof value === 'string' ? value : String(value) }));
  } catch (err) {
    console.log(JSON.stringify({
      ok: false,
      error: String(err && err.message ? err.message : err).slice(0, 200),
    }));
  }
})();
