from django.test import SimpleTestCase

from adminmitigationstrategy.views import (
    MIN_MITIGATION_ASSET_COUNT,
    _qualifies_for_mitigation_strategy,
)


class MitigationStrategyFilterTests(SimpleTestCase):
    def test_min_asset_count_is_four(self):
        self.assertEqual(MIN_MITIGATION_ASSET_COUNT, 4)

    def test_qualifies_only_when_more_than_three_assets(self):
        self.assertFalse(_qualifies_for_mitigation_strategy(1))
        self.assertFalse(_qualifies_for_mitigation_strategy(2))
        self.assertFalse(_qualifies_for_mitigation_strategy(3))
        self.assertTrue(_qualifies_for_mitigation_strategy(4))
        self.assertTrue(_qualifies_for_mitigation_strategy(5))
