"""Fake credentials, unique to each run, placed where stealers look.

None of them works anywhere. Reading one is recorded by the trace; sending one is seen by
the sink, in plain text or base64, hex or URL encoding.
"""

from __future__ import annotations

import base64
import secrets
import string
from dataclasses import dataclass, field

HOME = "/home/detonate"
_ALNUM = string.ascii_letters + string.digits
_UPPER = string.ascii_uppercase + string.digits


def _random(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


@dataclass(frozen=True)
class Canaries:
    run: str
    files: dict[str, str]  # path under HOME -> content
    env: dict[str, str]
    tokens: dict[str, str] = field(default_factory=dict)  # what it is -> secret value

    def paths(self) -> list[str]:
        return [f"{HOME}/{name}" for name in self.files]


def make() -> Canaries:
    run = _random(string.ascii_lowercase + string.digits, 12)
    tokens = {
        "npm token": "npm_" + _random(_ALNUM, 36),
        "PyPI token": "pypi-" + _random(_ALNUM, 48),
        "GitHub token": "ghp_" + _random(_ALNUM, 36),
        "AWS access key": "AKIA" + _random(_UPPER, 16),
        "AWS secret key": _random(_ALNUM, 40),
        "SSH key": _random(_ALNUM, 64),
        "OIDC request token": _random(_ALNUM, 40),
    }
    files = {
        ".npmrc": f"//registry.npmjs.org/:_authToken={tokens['npm token']}\n",
        ".pypirc": ("[distutils]\nindex-servers = pypi\n\n[pypi]\nusername = __token__\n"
                    f"password = {tokens['PyPI token']}\n"),
        ".aws/credentials": (f"[default]\naws_access_key_id = {tokens['AWS access key']}\n"
                             f"aws_secret_access_key = {tokens['AWS secret key']}\n"),
        ".ssh/id_ed25519": ("-----BEGIN OPENSSH PRIVATE KEY-----\n"
                            f"{tokens['SSH key']}\n-----END OPENSSH PRIVATE KEY-----\n"),
        ".git-credentials": f"https://detonate:{tokens['GitHub token']}@github.com\n",
    }
    env = {
        "NPM_TOKEN": tokens["npm token"],
        "NODE_AUTH_TOKEN": tokens["npm token"],
        "GITHUB_TOKEN": tokens["GitHub token"],
        "GH_TOKEN": tokens["GitHub token"],
        "AWS_ACCESS_KEY_ID": tokens["AWS access key"],
        "AWS_SECRET_ACCESS_KEY": tokens["AWS secret key"],
        "TWINE_PASSWORD": tokens["PyPI token"],
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": tokens["OIDC request token"],
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.invalid/oidc/token",
    }
    return Canaries(run, files, env, tokens)


def encodings(value: str) -> list[bytes]:
    """The forms a sent secret is looked for in: as is, hex, URL-encoded, and base64 at each
    of the three alignments it can have inside a longer encoded blob."""
    raw = value.encode()
    forms = [raw, raw.hex().encode(), raw.hex().upper().encode()]
    for shift in range(3):
        encoded = base64.b64encode(b"\0" * shift + raw)
        # Drop the characters that also depend on the bytes before and after the secret:
        # with one byte before it, the first two; with two, the first three.
        start = (0, 2, 3)[shift]
        end = len(encoded) - 4
        if end - start >= 16:
            forms.append(encoded[start:end])
    return forms


def found_in(data: bytes, canaries: dict[str, str]) -> list[str]:
    """Which secrets appear in `data`, in any of the forms above."""
    text = data.replace(b"%2B", b"+").replace(b"%2F", b"/").replace(b"%3D", b"=")
    return sorted(name for name, value in canaries.items()
                  if any(form in data or form in text for form in encodings(value)))
