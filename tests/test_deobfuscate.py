"""解混淆脚本的用例：识别和过滤的那几层，不依赖真包。

真实的 obfuscator.io 样例不好手工造（要 base64 + RC4），所以这里测「认不认得」
那一层：数组函数、解码函数、调用点、以及过滤噪音的规则。
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, ROOT)

import deobfuscate as d  # noqa: E402


class LooksLikeChannelTests(unittest.TestCase):
    def test_module_slash_method(self):
        self.assertTrue(d.looks_like_channel('app/getAppInfo'))
        self.assertTrue(d.looks_like_channel('window/isVisible'))

    def test_colon_and_dot_names(self):
        self.assertTrue(d.looks_like_channel('a:b'))
        self.assertTrue(d.looks_like_channel('ledger.add'))

    def test_rejects_obfuscation_key(self):
        # RC4 的 key 常是 4 个随机字符，别当通道
        self.assertFalse(d.looks_like_channel('0fuO'))
        self.assertFalse(d.looks_like_channel('k817'))

    def test_rejects_parseint_garbage(self):
        # parseInt 校验值：数字开头
        self.assertFalse(d.looks_like_channel('1359323lhJrXT'))

    def test_rejects_code_like(self):
        self.assertFalse(d.looks_like_channel('a b'))
        self.assertFalse(d.looks_like_channel('f(x)'))


class FindTests(unittest.TestCase):
    def test_finds_array_function(self):
        src = ("function _0xabc(){const _0x1=['\\x61','\\x62','\\x63','\\x64','\\x65','\\x66',"
               "'\\x67','\\x68','\\x69','\\x6a','\\x6b','\\x6c','\\x6d','\\x6e','\\x6f','\\x70',"
               "'\\x71','\\x72','\\x73','\\x74','\\x75','\\x76','\\x77','\\x78','\\x79','\\x7a',"
               "'\\x41','\\x42','\\x43','\\x44','\\x45','\\x46','\\x47','\\x48','\\x49','\\x4a',"
               "'\\x4b','\\x4c','\\x4d','\\x4e','\\x4f','\\x50','\\x51','\\x52','\\x53','\\x54',"
               "'\\x55','\\x56','\\x57','\\x58','\\x59','\\x5a'];"
               "_0xabc=function(){return _0x1};return _0xabc();}")
        name, body = d.find_array_function(src)
        self.assertEqual(name, '_0xabc')
        self.assertIn('_0xabc=function', body)

    def test_finds_decode_function(self):
        src = ("function _0xd(a,b){var e=[];for(var u=0;u<0x100;u++){e[u]=u;}"
               "for(var w=0;w<0x10;w++){q=q*0x40+1;}return decodeURIComponent('x');}")
        name, body = d.find_decode_function(src)
        self.assertEqual(name, '_0xd')

    def test_find_all_calls_keeps_function_name(self):
        src = "var x = _0x1a(0x700,'\\x77\\x32\\x40\\x4b');"
        calls = d.find_all_calls(src)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], '_0x1a')
        self.assertTrue(calls[0][1].startswith('_0x1a('))
        self.assertIn('0x700', calls[0][1])


if __name__ == '__main__':
    unittest.main()
