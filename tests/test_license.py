"""ADR-0010 decision 8 (Amendment A): the project says, in the three places a reader looks, that it is dedicated to
the public domain under CC0 1.0 Universal - the licence file, the package's metadata and the README."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_the_licence_file_is_the_cc0_legal_code():
    text = (ROOT / "LICENSE").read_text(encoding="ascii")
    lines = [x.strip() for x in text.splitlines() if x.strip()]
    assert lines[:2] == ["Creative Commons Legal Code", "CC0 1.0 Universal"]
    assert "Statement of Purpose" in text and "4. Limitations and Disclaimers." in text
    assert text.rstrip().endswith("this CC0 or use of the Work.")


def test_the_package_and_the_readme_name_it():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'license = {text = "CC0-1.0"}' in pyproject   # the form every setuptools from 61 on reads
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Licence\n", 1)[1]
    assert "[CC0 1.0 Universal](LICENSE)" in section and "no warranty" in section and "patent" in section
