"""The accuracy benchmark: Bomb Squad and GuardDog on the same malicious and benign packages.

It runs only on Linux CI (`.github/workflows/benchmark.yml`). Samples are fetched and
unpacked inside the job and never written to the repository. Results keep package names,
versions, rule IDs and levels, never sample content.
"""
