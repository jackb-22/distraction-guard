from guardctl.registry import Kind, kind_of
# Importing cli registers all the real commands via the @command decorator.
import guardctl.cli  # noqa: F401


def test_unknown_command_is_loosen():
    assert kind_of("this-command-does-not-exist") == Kind.LOOSEN


def test_tighten_commands():
    for name in ("block", "block-path", "add-term", "add-context-word", "enable-list"):
        assert kind_of(name) == Kind.TIGHTEN, name


def test_loosen_commands():
    for name in ("unblock", "passthrough", "allow-temp", "disable-list", "remove-term", "totp-enroll", "notify-setup", "emergency-off"):
        assert kind_of(name) == Kind.LOOSEN, name


def test_emergency_on_is_tighten():
    # emergency-off is LOOSEN (it's the panic button, and pre-lock LOOSEN
    # commands run instantly -- see _authorize); emergency-on re-applies
    # the redirect/blocking, so it's TIGHTEN like every other "make it
    # stricter" action.
    assert kind_of("emergency-on") == Kind.TIGHTEN


def test_neutral_commands():
    for name in ("status", "compile", "test-url", "log", "doctor"):
        assert kind_of(name) == Kind.NEUTRAL, name


def test_internal_commands():
    for name in ("_refresh", "_notify-flush", "_post-upgrade", "_expire"):
        assert kind_of(name) == Kind.INTERNAL, name
