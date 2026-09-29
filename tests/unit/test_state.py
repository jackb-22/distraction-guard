from guardctl.state import StateDir


def test_lock_flag_defaults_unlocked(tmp_path):
    s = StateDir(str(tmp_path))
    assert s.is_locked() is False


def test_set_and_read_lock_flag(tmp_path):
    s = StateDir(str(tmp_path))
    s.set_locked(True)
    assert s.is_locked() is True
    s.set_locked(False)
    assert s.is_locked() is False


def test_audit_log_append_and_read(tmp_path):
    s = StateDir(str(tmp_path))
    s.audit(command="block reddit.com", classification="tighten", auth="none", summary="Blocked reddit.com", sudo_user="jack")
    s.audit(command="unblock reddit.com", classification="loosen", auth="totp", summary="Unblocked reddit.com", sudo_user="jack")
    entries = s.read_audit()
    assert len(entries) == 2
    assert entries[0]["command"] == "block reddit.com"
    assert entries[1]["auth"] == "totp"


def test_audit_log_is_append_only_across_calls(tmp_path):
    s = StateDir(str(tmp_path))
    for i in range(5):
        s.audit(command=f"cmd{i}", classification="tighten", auth="none", summary="x", sudo_user="jack")
    assert len(s.read_audit(limit=100)) == 5
    assert len(s.read_audit(limit=2)) == 2


def test_read_json_missing_returns_default(tmp_path):
    s = StateDir(str(tmp_path))
    assert s.read_json("nope.json", {"x": 1}) == {"x": 1}


def test_write_read_json_roundtrip(tmp_path):
    s = StateDir(str(tmp_path))
    s.write_json("thing.json", {"a": 1, "b": [1, 2, 3]})
    assert s.read_json("thing.json", None) == {"a": 1, "b": [1, 2, 3]}


def test_write_json_is_atomic_no_tmp_left_behind(tmp_path):
    s = StateDir(str(tmp_path))
    s.write_json("thing.json", {"a": 1})
    assert not (tmp_path / "thing.json.tmp").exists()


def test_locked_context_manager_serializes(tmp_path):
    s = StateDir(str(tmp_path))
    order = []
    with s.locked():
        order.append("a")
    with s.locked():
        order.append("b")
    assert order == ["a", "b"]


def test_audit_never_chmods_an_existing_log(tmp_path, monkeypatch):
    # After `guardctl lock`, audit.log is append-only (chattr +a), where
    # chmod fails with EPERM -- that must not break every command.
    import os
    from guardctl.state import StateDir
    st = StateDir(str(tmp_path))
    st.audit(command="a", classification="tighten", auth="none", summary="a", sudo_user="jack")
    def no_chmod(*a, **k):
        raise PermissionError("append-only")
    monkeypatch.setattr(os, "chmod", no_chmod)
    st.audit(command="b", classification="tighten", auth="none", summary="b", sudo_user="jack")
    assert [e["command"] for e in st.read_audit()] == ["a", "b"]
    assert oct(os.stat(st.path("audit.log")).st_mode & 0o777) == "0o600"


def test_corrupt_lock_file_fails_closed(tmp_path):
    from guardctl.state import StateDir
    st = StateDir(str(tmp_path))
    assert st.is_locked() is False
    st.path("lock.json").write_text("{garbage")
    assert st.is_locked() is True
