"""预警引擎的用例：级别判定、去重、以及那条不许破的纪律。"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import jswarn  # noqa: E402


class LevelTests(unittest.TestCase):
    def test_direct_exec_is_high(self):
        self.assertEqual(jswarn.level_of('direct', 'exec'), 'high')

    def test_direct_file_write_is_high(self):
        self.assertEqual(jswarn.level_of('direct', 'file-write'), 'high')

    def test_direct_read_is_medium(self):
        self.assertEqual(jswarn.level_of('direct', 'file-read'), 'medium')

    def test_chain_is_medium(self):
        self.assertEqual(jswarn.level_of('chain', 'file-read'), 'medium')

    def test_borrowed_never_high_even_with_exec(self):
        """这条是设计守则 2 的底线：借来档 + 命令执行也不许进 high。"""
        self.assertEqual(jswarn.level_of('ambiguous', 'exec'), 'low')
        self.assertEqual(jswarn.level_of('ast_only', 'exec'), 'low')
        self.assertEqual(jswarn.level_of('ambiguous', 'file-write'), 'low')

    def test_unknown_tier_stays_low(self):
        self.assertEqual(jswarn.level_of('whatever', 'exec'), 'low')

    def test_unknown_sink_category(self):
        self.assertIsNone(jswarn.sink_category('not_a_danger_api'))


class BuildTests(unittest.TestCase):
    def facts(self, tiers, sinks=None):
        return {
            'channel_sink_tiers': tiers,
            'channel_sinks_ast': sinks or {
                ch: sorted(api_tiers) for ch, api_tiers in tiers.items()},
        }

    def test_one_channel_one_category_one_warning(self):
        # 同一通道挂两个写文件 API，只该出一条预警（规矩 2）
        facts = self.facts({'a:b': {'writeFile': 'direct', 'writeFileSync': 'direct'}})
        warns = jswarn.build_warnings(facts)
        self.assertEqual(len(warns), 1)
        self.assertEqual(warns[0]['rule_id'], 'sink-file-write')
        self.assertEqual(warns[0]['sinks'], ['writeFile', 'writeFileSync'])

    def test_different_categories_are_separate_warnings(self):
        facts = self.facts({'a:b': {'exec': 'direct', 'writeFile': 'direct'}})
        rules = sorted(w['rule_id'] for w in jswarn.build_warnings(facts))
        self.assertEqual(rules, ['sink-exec', 'sink-file-write'])

    def test_warning_carries_entity_and_tier(self):
        facts = self.facts({'a:b': {'exec': 'direct'}})
        warn = jswarn.build_warnings(facts)[0]
        self.assertEqual(warn['entity'], 'a:b')
        self.assertEqual(warn['tier'], 'direct')
        self.assertIn('rationale', warn)

    def test_warnings_are_sorted_high_first(self):
        facts = self.facts({
            'low:ch': {'exec': 'ambiguous'},
            'high:ch': {'exec': 'direct'},
        })
        levels = [w['level'] for w in jswarn.build_warnings(facts)]
        self.assertEqual(levels, ['high', 'low'])

    def test_no_tiers_no_warnings(self):
        self.assertEqual(jswarn.build_warnings({}), [])

    def test_category_representative_takes_strongest_tier(self):
        # 同类里一条 direct、一条 ambiguous：代表档该是 direct
        facts = self.facts({'a:b': {'writeFile': 'ambiguous', 'writeFileSync': 'direct'}})
        warn = jswarn.build_warnings(facts)[0]
        self.assertEqual(warn['tier'], 'direct')
        self.assertEqual(warn['level'], 'high')

    def test_borrowed_only_channel_lands_in_low(self):
        facts = self.facts({'a:b': {'exec': 'ast_only'}})
        warn = jswarn.build_warnings(facts)[0]
        self.assertEqual(warn['level'], 'low')
        self.assertIn('人工核', warn['rationale'])


class BuiltinRulesTests(unittest.TestCase):
    def test_load_rules_without_path_returns_builtin(self):
        rules = jswarn.load_rules(None)
        self.assertEqual(rules['levels'], 'builtin')


class EndToEndTests(unittest.TestCase):
    """真扫一个靶场，看事件流里发出来的预警对不对。"""

    def scan(self):
        import jsevents
        import ipcsurface as t
        asar = os.path.join(ROOT, 'examples', 'build', 'static-asar.asar')
        if not os.path.exists(asar):
            self.skipTest('靶场没构建，跳过')
        collected = []
        bus = jsevents.EventBus(None)
        bus.add_listener(collected.append)
        facts, _n, _b = t.analyse_asar(asar, events=bus)
        bus.close()
        return facts, collected

    def test_warnings_reference_existing_channels(self):
        facts, events = self.scan()
        channels = {e['payload']['name'] for e in events
                    if e['kind'] == 'discovery'}
        warns = [e['payload'] for e in events if e['kind'] == 'warning']
        self.assertTrue(warns, '靶场里应该至少有一条预警')
        # 规矩 1：预警必须能指回已有通道。收集后一次断言，别在循环里 assert
        orphans = [w['entity'] for w in warns if w['entity'] not in channels]
        self.assertFalse(orphans, '预警指不到通道：%r' % (orphans,))

    def test_no_borrowed_tier_in_high(self):
        _facts, events = self.scan()
        bad = [e['payload'] for e in events
               if e['kind'] == 'warning'
               and e['payload']['level'] == 'high'
               and e['payload']['tier'] in jswarn.BORROWED_TIERS]
        self.assertFalse(bad, '借来档不许进 high：%r' % (bad,))

    def test_warning_comes_before_done(self):
        _facts, events = self.scan()
        kinds = [e['kind'] for e in events]
        first_warn = kinds.index('warning') if 'warning' in kinds else None
        self.assertIsNotNone(first_warn, '应该发了预警')
        self.assertLess(first_warn, len(kinds) - 1,
                        'warning 不能在 done 之后（done 必须最后一条）')
        self.assertEqual(kinds[-1], 'lifecycle')
        self.assertEqual(events[-1]['payload']['stage'], 'done')


if __name__ == '__main__':
    unittest.main()
