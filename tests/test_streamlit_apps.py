from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_streamlit_apps_import_from_repo_source() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT / "src")])
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import streamlit_app; import streamlit_app_v2; import streamlit_app_v3_v5",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_streamlit_docs_reference_all_live_apps() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    deployment = (ROOT / "docs" / "streamlit_cloud.md").read_text(encoding="utf-8")
    wiki = (ROOT / "docs" / "wiki" / "Streamlit-Deployment.md").read_text(
        encoding="utf-8"
    )

    for content in (readme, deployment, wiki):
        assert "streamlit_app.py" in content
        assert "streamlit_app_v2.py" in content
        assert "streamlit_app_v3_v5.py" in content
        assert "terraform-guardrail-governance.streamlit.app" in content
