"""tools/gate.sh (M-REV E4, ADR-0001 B-3): only raqib/suspect/backends.py may
import the anthropic SDK. The gate is run on a scratch git repository that
holds a copy of it, so the real tree and its tests are not involved."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "tools" / "gate.sh"
BACKEND = 'def sdk():\n    import anthropic\n    return anthropic\n'


def gate(tmp_path, files):
    repo = tmp_path / "repo"
    (repo / "tools").mkdir(parents=True)
    shutil.copy(GATE, repo / "tools" / "gate.sh")
    (repo / "HANDOFF.md").write_text("# HANDOFF\n")
    for rel, text in dict({"raqib/suspect/backends.py": BACKEND}, **files).items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    proc = subprocess.run(["bash", str(repo / "tools" / "gate.sh")], capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


@pytest.mark.parametrize("rel, text, where", [
    ("raqib/other.py", "import anthropic\n", "raqib/other.py:1"),
    ("raqib/other.py", "x = 1\nfrom anthropic import Anthropic\n", "raqib/other.py:2"),
    ("raqib/other.py", "import os, anthropic.types as t\n", "raqib/other.py:1"),
    ("raqib/other.py", "import importlib\nm = importlib.import_module('anthropic')\n", "raqib/other.py:2"),
    ("raqib/other.py", "m = __import__('anthropic.types')\n", "raqib/other.py:1"),
    ("tests/conftest.py", "def f():\n    import anthropic\n", "tests/conftest.py:2"),
    ("tools/run.sh", "#!/bin/sh\npython3 -c 'import anthropic'\n", "tools/run.sh:2"),
    ("raqib/broken.py", "def (:\n", "raqib/broken.py:1: cannot be parsed"),
], ids=["import", "from-import", "import-list", "import-module", "dunder-import", "tests-too",
        "shell", "unparseable"])
def test_anthropic_outside_the_backend_is_red(tmp_path, rel, text, where):
    code, out = gate(tmp_path, {rel: text})
    assert code == 1, out
    assert "RED: anthropic imported outside raqib/suspect/backends.py" in out
    assert "[gate]   " + where in out
    assert "[gate] GREEN" not in out


def test_the_backend_and_mere_mentions_are_green(tmp_path):
    code, out = gate(tmp_path, {
        "raqib/doc.py": '"""We never import anthropic here."""\n# import anthropic\n'
                        'import anthropic_tools\nfrom .anthropic import x\nNAME = "anthropic"\n',
        "README.md": "pip install anthropic, then `import anthropic`.\n",
        "tools/note.sh": "#!/bin/sh\necho anthropic\n",
    })
    assert code == 0, out
    assert "anthropic SDK imported only by raqib/suspect/backends.py" in out and "[gate] GREEN" in out
