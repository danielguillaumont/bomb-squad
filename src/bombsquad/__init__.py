"""Bomb Squad: find what runs before anyone chooses to run it."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("bombsquad")
except PackageNotFoundError:  # running from a source tree without installation
    __version__ = "0+unknown"
