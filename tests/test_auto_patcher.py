"""
Unit tests for CHARLO Autonomous Code Auto-Patcher & Unified Git Diff Engine.
"""

import os
import tempfile
import pytest

from charlo.core.auto_patcher import AutoPatcher, PatchResult


def test_generate_diff_sql_injection():
    """Verify standard unified git diff generation for SQL injection flaw."""
    vulnerable_code = (
        'def get_user_profile(user_id):\n'
        '    cursor.execute(f"SELECT * FROM users WHERE id = \'{user_id}\'")\n'
        '    return cursor.fetchall()\n'
    )
    diff_str, desc = AutoPatcher.generate_diff("SQL_INJECTION", vulnerable_code, "profile_service.py")

    assert "--- a/profile_service.py" in diff_str
    assert "+++ b/profile_service.py" in diff_str
    assert "cursor.execute(" in diff_str
    assert "parameterized query" in desc.lower()


def test_generate_diff_xss_innerhtml():
    """Verify innerHTML replacement with safe textContent in git diff."""
    vulnerable_js = (
        'function renderComment(userInput) {\n'
        '    document.getElementById("output").innerHTML = userInput;\n'
        '}\n'
    )
    diff_str, desc = AutoPatcher.generate_diff("XSS", vulnerable_js, "comments.js")

    assert "--- a/comments.js" in diff_str
    assert "+++ b/comments.js" in diff_str
    assert "textContent" in diff_str
    assert "textContent" in desc


def test_generate_diff_hardcoded_secret():
    """Verify externalization of hardcoded API keys to environment variables."""
    vulnerable_py = (
        '# Service Configuration\n'
        'STRIPE_API_KEY = "sk_live_98374928374923847293847"\n'
        'DATABASE_PASSWORD = "SuperSecretPassword123!"\n'
    )
    diff_str, desc = AutoPatcher.generate_diff("HARDCODED_SECRET", vulnerable_py, "config.py")

    assert "os.environ.get" in diff_str
    assert "STRIPE_API_KEY" in diff_str
    assert "DATABASE_PASSWORD" in diff_str


def test_apply_patch_and_rollback(tmp_path):
    """Verify safe patch application, timestamped backup file creation, and rollback."""
    temp_file = tmp_path / "vulnerable_app.py"
    initial_content = (
        'def query_user(uid):\n'
        '    cursor.execute(f"SELECT * FROM users WHERE id = \'{uid}\'")\n'
        '    return cursor.fetchone()\n'
    )
    temp_file.write_text(initial_content, encoding="utf-8")

    # 1. Apply Patch
    res = AutoPatcher.apply_patch("FLAW-SQLI-01", str(temp_file), "SQL_INJECTION")
    assert isinstance(res, PatchResult)
    assert res.applied is True
    assert res.backup_file is not None
    assert os.path.exists(res.backup_file)

    # Content should now be remediated
    patched_content = temp_file.read_text(encoding="utf-8")
    assert "%s" in patched_content
    assert res.backup_file.endswith(".bak")

    # 2. Rollback
    rollback_ok = AutoPatcher.rollback_patch(res.backup_file)
    assert rollback_ok is True

    # Restored content should match initial
    restored_content = temp_file.read_text(encoding="utf-8")
    assert restored_content == initial_content


def test_apply_patch_missing_file():
    """Verify graceful handling when target file path does not exist."""
    res = AutoPatcher.apply_patch("FLAW-002", "C:/nonexistent/missing_file.py", "SQL_INJECTION")
    assert res.applied is False
    assert "File not found" in res.message
