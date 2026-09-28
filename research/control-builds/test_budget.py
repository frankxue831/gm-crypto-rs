import unittest
from budget import remaining_seconds

class BudgetTests(unittest.TestCase):
    def test_setup_time_is_subtracted_before_ten_minute_reserve(self):
        self.assertEqual(remaining_seconds(100,400),4490)
        self.assertEqual(remaining_seconds(100,100),4790)

    def test_expired_or_future_clock_refuses_preparation(self):
        for now in (99,4900,5500):
            with self.assertRaises(ValueError):remaining_seconds(100,now)

if __name__=='__main__':unittest.main()
