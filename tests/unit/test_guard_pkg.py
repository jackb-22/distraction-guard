"""bin/guard-pkg has no .py extension, so import it via importlib with an
explicit loader (same trick needed for any extensionless script module)."""
import importlib.util
import os
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[2] / "bin" / "guard-pkg"


@pytest.fixture
def guard_pkg(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    # No .py suffix, so spec_from_file_location can't infer a loader --
    # build one explicitly (same trick needed for any extensionless script).
    loader = SourceFileLoader("guard_pkg_under_test", str(MODULE_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _run(guard_pkg, monkeypatch, argv, execv_calls):
    monkeypatch.setattr(sys, "argv", ["guard-pkg", *argv])
    monkeypatch.setattr(os, "execv", lambda path, args: execv_calls.append((path, args)))
    return guard_pkg.main()


def test_non_root_refused(guard_pkg, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    calls = []
    rc = _run(guard_pkg, monkeypatch, ["update"], calls)
    assert rc == 1
    assert calls == []


def test_update_execs_pacman_syu(guard_pkg, monkeypatch):
    calls = []
    rc = _run(guard_pkg, monkeypatch, ["update"], calls)
    assert calls[0][1] == [guard_pkg.PACMAN, "-Syu", "--noconfirm"]


def test_install_valid_names(guard_pkg, monkeypatch):
    calls = []
    _run(guard_pkg, monkeypatch, ["install", "htop", "ripgrep"], calls)
    assert calls[0][1] == [guard_pkg.PACMAN, "-S", "--needed", "--noconfirm", "--", "htop", "ripgrep"]


def test_install_rejects_bad_name(guard_pkg, monkeypatch, capsys):
    calls = []
    rc = _run(guard_pkg, monkeypatch, ["install", "--config=/tmp/evil"], calls)
    assert rc == 1
    assert calls == []


def test_install_rejects_flag_like_name(guard_pkg, monkeypatch):
    calls = []
    rc = _run(guard_pkg, monkeypatch, ["install", "-U"], calls)
    assert rc == 1
    assert calls == []


def test_remove_refuses_protected_package(guard_pkg, monkeypatch):
    calls = []
    rc = _run(guard_pkg, monkeypatch, ["remove", "nftables"], calls)
    assert rc == 1
    assert calls == []


def test_remove_allows_unprotected_package(guard_pkg, monkeypatch):
    calls = []
    _run(guard_pkg, monkeypatch, ["remove", "htop"], calls)
    assert calls[0][1] == [guard_pkg.PACMAN, "-Rns", "--noconfirm", "--", "htop"]


def test_update_with_extra_args_rejected(guard_pkg, monkeypatch):
    calls = []
    rc = _run(guard_pkg, monkeypatch, ["update", "extra"], calls)
    assert rc == 1
    assert calls == []


def test_unknown_action_rejected(guard_pkg, monkeypatch):
    calls = []
    rc = _run(guard_pkg, monkeypatch, ["bogus"], calls)
    assert rc == 1
    assert calls == []


def test_no_args_rejected(guard_pkg, monkeypatch):
    calls = []
    rc = _run(guard_pkg, monkeypatch, [], calls)
    assert rc == 1


def test_install_refuses_nm_vpn_plugins(guard_pkg, monkeypatch):
    calls = []
    assert _run(guard_pkg, monkeypatch, ["install", "htop", "networkmanager-openvpn"], calls) == 1
    assert calls == []


def test_remove_refuses_lock_dependencies(guard_pkg, monkeypatch):
    for pkg in ("polkit", "shadow", "util-linux", "podman"):
        calls = []
        assert _run(guard_pkg, monkeypatch, ["remove", pkg], calls) == 1, pkg
        assert calls == []
