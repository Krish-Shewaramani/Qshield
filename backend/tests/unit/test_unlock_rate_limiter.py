import threading
import unittest

from backend.app.key_management.unlock_rate_limiter import (
    UnlockAdmissionError,
    UnlockCooldownError,
    UnlockRateLimiter,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _fail(limiter: UnlockRateLimiter, identifier: str) -> None:
    with limiter.admit(identifier) as attempt:
        attempt.authentication_failed()


class UnlockRateLimiterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = FakeClock()

    def test_five_failures_trigger_fixed_cooldown_without_extension(self) -> None:
        limiter = UnlockRateLimiter(clock=self.clock, global_capacity=100)
        identifier = "a" * 64
        for _ in range(5):
            _fail(limiter, identifier)
        with self.assertRaises(UnlockCooldownError):
            limiter.admit(identifier)
        self.clock.advance(25)
        with self.assertRaises(UnlockCooldownError):
            limiter.admit(identifier)
        self.clock.advance(5)
        with limiter.admit(identifier):
            pass

    def test_expired_failures_do_not_contribute_to_cooldown_threshold(self) -> None:
        limiter = UnlockRateLimiter(clock=self.clock, global_capacity=100)
        identifier = "a" * 64
        for _ in range(4):
            _fail(limiter, identifier)

        self.clock.advance(601)
        _fail(limiter, identifier)
        for _ in range(3):
            _fail(limiter, identifier)
        # Four failures inside the current window are below the threshold;
        # the four older failures must have been discarded.
        with limiter.admit(identifier):
            pass
        _fail(limiter, identifier)
        with self.assertRaises(UnlockCooldownError):
            limiter.admit(identifier)

    def test_cooldown_attempt_spends_global_token_and_recovers_after_refill(self) -> None:
        limiter = UnlockRateLimiter(clock=self.clock, global_capacity=2)
        cooling = "a" * 64
        other = "b" * 64
        for index in range(5):
            _fail(limiter, cooling)
            if index < 4:
                self.clock.advance(2)

        # The fifth failure establishes cooldown at t=8 with one token left.
        with self.assertRaises(UnlockCooldownError):
            limiter.admit(cooling)
        # Cooldown rejection consumed that token, so another key is globally
        # denied until the bucket refills.
        with self.assertRaises(UnlockAdmissionError):
            limiter.admit(other)
        self.clock.advance(2)
        with limiter.admit(other):
            pass

        # The cooldown has not been extended by rejected attempts. Once it
        # expires, the original key is eligible again.
        self.clock.advance(28)
        with limiter.admit(cooling):
            pass

    def test_success_resets_only_that_keys_failure_state(self) -> None:
        limiter = UnlockRateLimiter(clock=self.clock, global_capacity=100)
        first, second = "a" * 64, "b" * 64
        for _ in range(4):
            _fail(limiter, first)
        _fail(limiter, second)
        with limiter.admit(first) as attempt:
            attempt.authentication_succeeded()
        for _ in range(4):
            _fail(limiter, first)
        with limiter.admit(first):
            pass
        for _ in range(4):
            _fail(limiter, second)
        with self.assertRaises(UnlockCooldownError):
            limiter.admit(second)

    def test_global_bucket_capacity_and_fractional_refill(self) -> None:
        limiter = UnlockRateLimiter(clock=self.clock)
        for i in range(4):
            with limiter.admit(f"{i:064x}"):
                pass
        with self.assertRaises(UnlockAdmissionError):
            limiter.admit("f" * 64)
        self.clock.advance(1)
        with self.assertRaises(UnlockAdmissionError):
            limiter.admit("f" * 64)
        self.clock.advance(1)
        with limiter.admit("f" * 64):
            pass

    def test_excess_concurrent_unlock_is_rejected_without_waiting(self) -> None:
        limiter = UnlockRateLimiter(clock=self.clock, global_capacity=2)
        entered = threading.Event()
        release = threading.Event()
        errors: list[BaseException] = []

        def hold_slot() -> None:
            try:
                with limiter.admit("a" * 64):
                    entered.set()
                    if not release.wait(timeout=5):
                        raise AssertionError("test release event was not signaled")
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=hold_slot)
        worker.start()
        self.assertTrue(entered.wait(timeout=5))
        with self.assertRaises(UnlockAdmissionError):
            limiter.admit("b" * 64)
        release.set()
        worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        # The concurrent rejection itself spent the second global token.
        with self.assertRaises(UnlockAdmissionError):
            limiter.admit("c" * 64)
        self.clock.advance(2)
        with limiter.admit("c" * 64):
            pass

    def test_state_is_bounded_and_active_cooldowns_are_not_evicted(self) -> None:
        limiter = UnlockRateLimiter(clock=self.clock, global_capacity=2000)
        cooling = "a" * 64
        for _ in range(5):
            _fail(limiter, cooling)
        for index in range(511):
            _fail(limiter, f"{index + 1:064x}")
        self.assertEqual(limiter.tracked_key_count, 512)
        _fail(limiter, "f" * 64)
        self.assertEqual(limiter.tracked_key_count, 512)
        with self.assertRaises(UnlockCooldownError):
            limiter.admit(cooling)

    def test_invalid_identifiers_are_not_tracked_per_key(self) -> None:
        limiter = UnlockRateLimiter(clock=self.clock)
        with limiter.admit("not-a-key-id") as attempt:
            attempt.authentication_failed()
        self.assertEqual(limiter.tracked_key_count, 0)


if __name__ == "__main__":
    unittest.main()
