"""Detonation: install a package in a throwaway container and record what it does.

The container has no host mounts, unique fake credentials, and a network that reaches only
a local sink. Static analysis stays the default; detonation only adds observations, and
something not observed is never cleared, because payloads can be time-gated or conditional.
"""
