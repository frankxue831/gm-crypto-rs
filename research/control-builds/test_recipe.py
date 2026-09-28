"""Research generator checks; generated leaky crate sources stay in temp workspaces."""
from pathlib import Path
import tempfile
import unittest
from recipe import patch, helper, variants


class RecipeTests(unittest.TestCase):
    def test_counts_are_pinned_not_timing_tunable(self):
        self.assertEqual(variants('ct_fn_invert'), [('sham', 0, 0), ('modest-left',16,0), ('modest-right',16,1), ('gross-left',1024,0), ('gross-right',1024,1)])
        self.assertEqual([x[1] for x in variants('ct_hmac_sm3')], [0,1,1,64,64])
        with self.assertRaises(ValueError): variants('other')

    def test_barriers_and_predicate_are_shared_with_sham(self):
        for target in ('ct_fn_invert', 'ct_fp_invert', 'ct_sign_k_class'):
            for name, count, direction in variants(target):
                source=helper(target,count,direction,False)
                self.assertIn('black_box(x.retrieve().to_be_bytes()[0] >> 7)',source)
                self.assertIn('state = black_box(black_box(state).square());',source)
                self.assertIn(f'for _ in 0..{count}',source)
                self.assertNotIn('Atomic',source)
                self.assertIn('WORK.fetch_add(1',helper(target,count,direction,True))

    def test_hmac_has_scratch_state_and_no_finalize(self):
        source=helper('ct_hmac_sm3',64,1,False)
        self.assertIn('block[..32].copy_from_slice(key)',source)
        self.assertIn('block[32..].copy_from_slice(key)',source)
        self.assertIn('black_box(&mut state).update(black_box(&block))',source)
        self.assertNotIn('finalize',source)
        self.assertIn('let block = black_box(block);',source)
        self.assertLess(source.index('let block = black_box(block);'),source.index('if predicate =='))

    def test_changed_anchor_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); p=root/'crates/gmcrypto-core/src';p.mkdir(parents=True)
            (p/'lib.rs').write_text('// fixture\n')
            (p/'sm2').mkdir();(p/'sm2/sign.rs').write_text('// missing anchor\n')
            with self.assertRaisesRegex(ValueError,'anchor'):
                patch(root,'ct_sign_k_class','modest-left',False)


if __name__=='__main__':unittest.main()
