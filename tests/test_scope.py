import unittest

from trace_the_leak_security.scope import ScopeError, ScopeGuard


class ScopeGuardTests(unittest.TestCase):
    def test_requires_confirmation(self) -> None:
        guard = ScopeGuard(["example.test"])
        with self.assertRaises(ScopeError):
            guard.check("example.test")

    def test_accepts_authorized_subdomain(self) -> None:
        guard = ScopeGuard(["example.test"])
        self.assertEqual(guard.check("lab.example.test", confirmed=True), "lab.example.test")

    def test_rejects_lookalike_domain(self) -> None:
        guard = ScopeGuard(["example.test"])
        with self.assertRaises(ScopeError):
            guard.check("example.test.attacker.test", confirmed=True)

    def test_rejects_empty_allowlist(self) -> None:
        guard = ScopeGuard([])
        with self.assertRaises(ScopeError):
            guard.check("127.0.0.1", confirmed=True)


if __name__ == "__main__":
    unittest.main()
