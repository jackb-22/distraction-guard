"""Command registry: classifies every guardctl subcommand as TIGHTEN
(instant, no code), LOOSEN (needs a friend code once locked), or NEUTRAL
(read-only). An unregistered/unknown command is always treated as LOOSEN --
the ratchet fails toward "ask the friend," never toward "just do it."
"""
from __future__ import annotations

from enum import Enum
from typing import Callable, NamedTuple


class Kind(Enum):
    TIGHTEN = "tighten"
    LOOSEN = "loosen"
    NEUTRAL = "neutral"
    INTERNAL = "internal"  # systemd-triggered only (_refresh, _notify-flush,
    # _post-upgrade, _expire) -- refuses to run when SUDO_USER is set, so
    # jack can't invoke these as a side door around the ratchet.


class Command(NamedTuple):
    name: str
    kind: Kind
    handler: Callable
    min_args: int = 0
    max_args: int | None = None


_REGISTRY: dict[str, Command] = {}


def command(name: str, kind: Kind, *, min_args: int = 0, max_args: int | None = None):
    def deco(fn):
        _REGISTRY[name] = Command(name, kind, fn, min_args, max_args)
        return fn
    return deco


def get(name: str) -> Command | None:
    return _REGISTRY.get(name)


def kind_of(name: str) -> Kind:
    """Unknown command -> LOOSEN. This is the fail-safe default the tests
    pin down (tests/unit/test_registry.py::test_unknown_command_is_loosen)."""
    cmd = _REGISTRY.get(name)
    return cmd.kind if cmd is not None else Kind.LOOSEN


def all_commands() -> dict[str, Command]:
    return dict(_REGISTRY)
