"""M8.2 E5 (ADR-0009 decision 4): the rule form in the window and Remove, with a display (Tk 8.6; the
windows jobs run them). Every Tk test ends what it starts (conftest: the root destroyed, threads joined)."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from raqib import app, overlay, ruleform  # noqa: E402
from test_app_redo import _window, tk_or_skip  # noqa: E402


@pytest.fixture
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    overlay._MEASURED.clear()
    yield path
    overlay._MEASURED.clear()


def _focus_chain(root, start, n):
    seen, w = [], start
    for _ in range(n):
        seen.append(w)
        w = w.tk_focusNext()
    return seen


def test_tk_m82_new_rule_fill_test_add_the_row_appears_then_remove(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path)
        root.deiconify()   # key events reach a window that is on the screen (as test_app_redo's Enter test does)
        root.geometry("900x600")
        window.show_rules()
        window.tick()
        root.update()
        # E5: New rule is the screen's primary action; Add rule file... stays, secondary
        assert window.rules_new_button.winfo_manager() == "pack" and window.rules_add_button.winfo_manager() == "pack"
        assert str(window.rules_new_button.cget("style")) == "Primary.TButton"
        assert str(window.rules_add_button.cget("style")) != "Primary.TButton"
        window.rules_new_button.invoke()
        root.update()
        assert window.screen == "ruleform" and window.rules_form_add_button.winfo_manager() == "pack"
        assert window.rules_form_add_button.instate(["disabled"])   # nothing tested yet
        assert window.verdict.cget("text") == "A new rule, from a form"
        texts = [b.cget("text") for b in window.form_fields["when"].master.winfo_children()]
        assert texts == ["A program is run", "A file under a place is touched", "A network host is reached",
                         "A tool is used"]
        # the examples follow the first name
        window.form_vars["id"].set("MY-TF")
        window.form_vars["values"].set("terraform, tofu")
        assert (window.form_vars["fires"].get(), window.form_vars["quiet"].get()) == ("terraform", "ls")
        window.form_vars["when"].set("tool")
        window.form_vars["values"].set("WebSearch")
        assert (window.form_vars["fires"].get(), window.form_vars["quiet"].get()) == ("WebSearch", "Read")
        window.form_vars["fires"].set("WebFetch")   # the person's own example is kept
        window.form_vars["values"].set("WebSearch, WebFetch")
        assert window.form_vars["fires"].get() == "WebFetch"
        window.form_vars["when"].set("program")
        window.form_vars["values"].set("terraform, tofu")
        window.form_vars["fires"].set("terraform")
        # a refusal beside its field, by the keyboard (Enter on Test)
        window.form_vars["id"].set("my tf")
        window.rules_form_test_button.focus_force()
        root.update()
        window.rules_form_test_button.event_generate(app.KEYS["act"][0])
        root.update()
        said = window.form_said["id"]
        assert said.winfo_manager() == "pack" and "upper-case letters" in said.cget("text")
        assert window.verdict.cget("text") == "The rule was refused" and root.focus_get() is window.form_fields["id"]
        assert overlay.user_dir(str(home)) and not Path(overlay.user_dir(str(home))).exists()
        # Test passes: Add is enabled for these answers only
        window.form_vars["id"].set("MY-TF")
        window.rules_form_test()
        root.update()
        assert not said.winfo_manager() and window.rules_form_add_button.instate(["!disabled"])
        shown = window.form_text.get("1.0", "end")
        assert 'id: "MY-TF"' in shown and "on your records: no trace or host source file" in shown
        assert window.verdict.cget("text") == "The test passed: the rule can be added"
        window.form_vars["severity"].set("low")
        assert window.rules_form_add_button.instate(["disabled"])   # changed answers: Test again
        window.form_vars["severity"].set("medium")
        assert window.rules_form_add_button.instate(["!disabled"])
        assert not Path(overlay.user_dir(str(home))).exists()   # Test wrote nothing in rules.d
        window.rules_form_add_button.invoke()
        root.update()
        assert window.screen == "rules"
        row = next(i for i, _ in window.rule_rows if i["id"] == "MY-TF")
        assert row["origin"] == "user" and "user" in row["pills"]
        assert (Path(overlay.user_dir(str(home))) / "MY-TF" / "MY-TF.yaml").is_file()
        assert ("MY-NONE", "remove") not in window.rule_widgets and ("NET-TOOL", "remove") not in window.rule_widgets
        # E4: Remove asks once, beside its row; Keep keeps it; Remove it removes it and says so
        window.rule_widgets[("MY-TF", "remove")].invoke()
        root.update()
        assert root.focus_get() is window.rule_widgets[("MY-TF", "confirm")]
        window.rule_widgets[("MY-TF", "keep")].invoke()
        root.update()
        assert (Path(overlay.user_dir(str(home))) / "MY-TF").is_dir() and ("MY-TF", "confirm") not in window.rule_widgets
        window.rule_widgets[("MY-TF", "remove")].invoke()
        root.update()
        window.rule_widgets[("MY-TF", "confirm")].focus_force()
        root.update()
        window.rule_widgets[("MY-TF", "confirm")].event_generate(app.KEYS["act"][0])
        root.update()
        assert not (Path(overlay.user_dir(str(home))) / "MY-TF").exists()
        assert "MY-TF" not in [i["id"] for i, _ in window.rule_rows]
        assert "MY-TF removed" in window.detail.cget("text")
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_m82_the_form_is_keyboard_throughout(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = _window(tkinter, root, home, tmp_path)
        root.deiconify()
        root.geometry("900x600")
        window.rules_new()
        root.update()
        chain = _focus_chain(root, window.form_fields["id"], 40)
        for name in ruleform.FIELDS:
            assert window.form_fields[name] in chain, name
        assert window.rules_form_test_button in chain and window.rules_form_back in chain
        radio = window.form_fields["when"].master.winfo_children()[3]
        radio.focus_force()
        root.update()
        radio.event_generate(app.KEYS["act"][0])   # Enter chooses, as Space does
        root.update()
        assert window.form_vars["when"].get() == "tool"
        window.rules_form_back.focus_force()
        root.update()
        window.rules_form_back.event_generate(app.KEYS["act"][0])
        root.update()
        assert window.screen == "rules" and root.focus_get() is window.rules_new_button
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()
