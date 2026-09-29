"""dg_policy must import with zero third-party dependencies (stdlib only),
so guardctl (a plain root script, no venv) can use it directly."""
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_dg_policy_imports_with_isolated_stdlib_only():
    # -I (isolated mode) drops PYTHONPATH/env *and* the cwd auto-add to
    # sys.path -- matching exactly how the deployed guardctl script loads
    # dg_policy in production (explicit sys.path.insert, no reliance on cwd
    # or environment). See bin/guardctl.
    code = (
        f"import sys; sys.path.insert(0, {str(REPO_ROOT)!r}); "
        "import dg_policy; import dg_policy.hosts; import dg_policy.text"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
