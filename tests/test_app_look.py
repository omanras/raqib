"""M7.6b (ADR-0008 decision 6): the window's look. The theme table, the
level -> colour mapping, the Treeview columns and their sort keys, the
detail pane, the Rules table's overlay state, the header's rules item, the
first-run text and the doctrine, the footer, the tray tip; then one small
Tk test (skipped without tkinter or a display) that builds every screen at
900x600 and checks that nothing asks for more."""
from __future__ import annotations

import ast
import datetime
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from raqib import app, host, overlay, tray  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
from test_app import FakeSession, TkSession, tk_or_skip, until  # noqa: E402
from test_app_host import CATALOG, FakeHostWatch, TkHost, inv, probe  # noqa: E402

LEVELS = ("clean", "alarm", "incomplete", "note", "hole", "suppressed")
HEX = re.compile(r"#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3}){0,3}")
# REDO C-6: Tk's colour names (colors.n: the X11 list, grayN/greyN 0..100 included, and Tk's additions), lower
# case without spaces (Tk ignores case and accepts "alice blue" as "AliceBlue"); "amber" is not Tk's but is refused.
TK_NAMES = set((
    "aliceblue antiquewhite antiquewhite1 antiquewhite2 antiquewhite3 antiquewhite4 aqua aquamarine aquamarine1 "
    "aquamarine2 aquamarine3 aquamarine4 azure azure1 azure2 azure3 azure4 beige bisque bisque1 bisque2 bisque3 "
    "bisque4 black blanchedalmond blue blue1 blue2 blue3 blue4 blueviolet brown brown1 brown2 brown3 brown4 "
    "burlywood burlywood1 burlywood2 burlywood3 burlywood4 cadetblue cadetblue1 cadetblue2 cadetblue3 cadetblue4 "
    "chartreuse chartreuse1 chartreuse2 chartreuse3 chartreuse4 chocolate chocolate1 chocolate2 chocolate3 "
    "chocolate4 coral coral1 coral2 coral3 coral4 cornflowerblue cornsilk cornsilk1 cornsilk2 cornsilk3 cornsilk4 "
    "crimson cyan cyan1 cyan2 cyan3 cyan4 darkblue darkcyan darkgoldenrod darkgoldenrod1 darkgoldenrod2 "
    "darkgoldenrod3 darkgoldenrod4 darkgray darkgreen darkgrey darkkhaki darkmagenta darkolivegreen darkolivegreen1 "
    "darkolivegreen2 darkolivegreen3 darkolivegreen4 darkorange darkorange1 darkorange2 darkorange3 darkorange4 "
    "darkorchid darkorchid1 darkorchid2 darkorchid3 darkorchid4 darkred darksalmon darkseagreen darkseagreen1 "
    "darkseagreen2 darkseagreen3 darkseagreen4 darkslateblue darkslategray darkslategray1 darkslategray2 "
    "darkslategray3 darkslategray4 darkslategrey darkturquoise darkviolet debianred deeppink deeppink1 deeppink2 "
    "deeppink3 deeppink4 deepskyblue deepskyblue1 deepskyblue2 deepskyblue3 deepskyblue4 dimgray dimgrey dodgerblue "
    "dodgerblue1 dodgerblue2 dodgerblue3 dodgerblue4 firebrick firebrick1 firebrick2 firebrick3 firebrick4 "
    "floralwhite forestgreen fuchsia gainsboro ghostwhite gold gold1 gold2 gold3 gold4 goldenrod goldenrod1 "
    "goldenrod2 goldenrod3 goldenrod4 gray gray0 gray1 gray10 gray100 gray11 gray12 gray13 gray14 gray15 gray16 "
    "gray17 gray18 gray19 gray2 gray20 gray21 gray22 gray23 gray24 gray25 gray26 gray27 gray28 gray29 gray3 gray30 "
    "gray31 gray32 gray33 gray34 gray35 gray36 gray37 gray38 gray39 gray4 gray40 gray41 gray42 gray43 gray44 gray45 "
    "gray46 gray47 gray48 gray49 gray5 gray50 gray51 gray52 gray53 gray54 gray55 gray56 gray57 gray58 gray59 gray6 "
    "gray60 gray61 gray62 gray63 gray64 gray65 gray66 gray67 gray68 gray69 gray7 gray70 gray71 gray72 gray73 gray74 "
    "gray75 gray76 gray77 gray78 gray79 gray8 gray80 gray81 gray82 gray83 gray84 gray85 gray86 gray87 gray88 gray89 "
    "gray9 gray90 gray91 gray92 gray93 gray94 gray95 gray96 gray97 gray98 gray99 green green1 green2 green3 green4 "
    "greenyellow grey grey0 grey1 grey10 grey100 grey11 grey12 grey13 grey14 grey15 grey16 grey17 grey18 grey19 "
    "grey2 grey20 grey21 grey22 grey23 grey24 grey25 grey26 grey27 grey28 grey29 grey3 grey30 grey31 grey32 grey33 "
    "grey34 grey35 grey36 grey37 grey38 grey39 grey4 grey40 grey41 grey42 grey43 grey44 grey45 grey46 grey47 grey48 "
    "grey49 grey5 grey50 grey51 grey52 grey53 grey54 grey55 grey56 grey57 grey58 grey59 grey6 grey60 grey61 grey62 "
    "grey63 grey64 grey65 grey66 grey67 grey68 grey69 grey7 grey70 grey71 grey72 grey73 grey74 grey75 grey76 grey77 "
    "grey78 grey79 grey8 grey80 grey81 grey82 grey83 grey84 grey85 grey86 grey87 grey88 grey89 grey9 grey90 grey91 "
    "grey92 grey93 grey94 grey95 grey96 grey97 grey98 grey99 honeydew honeydew1 honeydew2 honeydew3 honeydew4 "
    "hotpink hotpink1 hotpink2 hotpink3 hotpink4 indianred indianred1 indianred2 indianred3 indianred4 indigo ivory "
    "ivory1 ivory2 ivory3 ivory4 khaki khaki1 khaki2 khaki3 khaki4 lavender lavenderblush lavenderblush1 "
    "lavenderblush2 lavenderblush3 lavenderblush4 lawngreen lemonchiffon lemonchiffon1 lemonchiffon2 lemonchiffon3 "
    "lemonchiffon4 lightblue lightblue1 lightblue2 lightblue3 lightblue4 lightcoral lightcyan lightcyan1 lightcyan2 "
    "lightcyan3 lightcyan4 lightgoldenrod lightgoldenrod1 lightgoldenrod2 lightgoldenrod3 lightgoldenrod4 "
    "lightgoldenrodyellow lightgray lightgreen lightgrey lightpink lightpink1 lightpink2 lightpink3 lightpink4 "
    "lightsalmon lightsalmon1 lightsalmon2 lightsalmon3 lightsalmon4 lightseagreen lightskyblue lightskyblue1 "
    "lightskyblue2 lightskyblue3 lightskyblue4 lightslateblue lightslategray lightslategrey lightsteelblue "
    "lightsteelblue1 lightsteelblue2 lightsteelblue3 lightsteelblue4 lightyellow lightyellow1 lightyellow2 "
    "lightyellow3 lightyellow4 lime limegreen linen magenta magenta1 magenta2 magenta3 magenta4 maroon maroon1 "
    "maroon2 maroon3 maroon4 mediumaquamarine mediumblue mediumorchid mediumorchid1 mediumorchid2 mediumorchid3 "
    "mediumorchid4 mediumpurple mediumpurple1 mediumpurple2 mediumpurple3 mediumpurple4 mediumseagreen "
    "mediumslateblue mediumspringgreen mediumturquoise mediumvioletred midnightblue mintcream mistyrose mistyrose1 "
    "mistyrose2 mistyrose3 mistyrose4 moccasin navajowhite navajowhite1 navajowhite2 navajowhite3 navajowhite4 navy "
    "navyblue oldlace olive olivedrab olivedrab1 olivedrab2 olivedrab3 olivedrab4 orange orange1 orange2 orange3 "
    "orange4 orangered orangered1 orangered2 orangered3 orangered4 orchid orchid1 orchid2 orchid3 orchid4 "
    "palegoldenrod palegreen palegreen1 palegreen2 palegreen3 palegreen4 paleturquoise paleturquoise1 "
    "paleturquoise2 paleturquoise3 paleturquoise4 palevioletred palevioletred1 palevioletred2 palevioletred3 "
    "palevioletred4 papayawhip peachpuff peachpuff1 peachpuff2 peachpuff3 peachpuff4 peru pink pink1 pink2 pink3 "
    "pink4 plum plum1 plum2 plum3 plum4 powderblue purple purple1 purple2 purple3 purple4 rebeccapurple red red1 "
    "red2 red3 red4 rosybrown rosybrown1 rosybrown2 rosybrown3 rosybrown4 royalblue royalblue1 royalblue2 "
    "royalblue3 royalblue4 saddlebrown salmon salmon1 salmon2 salmon3 salmon4 sandybrown seagreen seagreen1 "
    "seagreen2 seagreen3 seagreen4 seashell seashell1 seashell2 seashell3 seashell4 sienna sienna1 sienna2 sienna3 "
    "sienna4 silver skyblue skyblue1 skyblue2 skyblue3 skyblue4 slateblue slateblue1 slateblue2 slateblue3 "
    "slateblue4 slategray slategray1 slategray2 slategray3 slategray4 slategrey snow snow1 snow2 snow3 snow4 "
    "springgreen springgreen1 springgreen2 springgreen3 springgreen4 steelblue steelblue1 steelblue2 steelblue3 "
    "steelblue4 tan tan1 tan2 tan3 tan4 teal thistle thistle1 thistle2 thistle3 thistle4 tomato tomato1 tomato2 "
    "tomato3 tomato4 turquoise turquoise1 turquoise2 turquoise3 turquoise4 violet violetred violetred1 violetred2 "
    "violetred3 violetred4 webgray webgreen webgrey webmaroon webpurple wheat wheat1 wheat2 wheat3 wheat4 white "
    "whitesmoke x11gray x11green x11grey x11maroon x11purple yellow yellow1 yellow2 yellow3 yellow4 yellowgreen "
    "amber").split())
# the Windows system colours Tk documents (and any other "system..." word: macOS has its own)
SYSTEM_NAMES = {"system3ddarkshadow", "system3dlight", "systemactiveborder", "systemactivecaption",
                "systemappworkspace", "systembackground", "systembuttonface", "systembuttonhighlight",
                "systembuttonshadow", "systembuttontext", "systemcaptiontext", "systemdisabledtext",
                "systemgraytext", "systemhighlight", "systemhighlighttext", "systeminactiveborder",
                "systeminactivecaption", "systeminactivecaptiontext", "systeminfobackground", "systeminfotext",
                "systemmenu", "systemmenutext", "systemscrollbar", "systemwindow", "systemwindowframe",
                "systemwindowtext"}
COLOUR_OPTIONS = {"fg", "bg", "foreground", "background", "activeforeground", "activebackground",
                  "disabledforeground", "highlightbackground", "highlightcolor", "insertbackground",
                  "selectbackground", "selectforeground", "selectcolor", "troughcolor", "bordercolor",
                  "lightcolor", "darkcolor", "fieldbackground", "insertcolor", "arrowcolor", "readonlybackground",
                  "inactiveselectbackground", "focuscolor"}
WAIT = 30


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setenv("HOME", str(path))
    monkeypatch.setenv("USERPROFILE", str(path))
    return path


# --- E1: one theme table; the exit-code scheme; a word beside every colour ------------------------------------

def test_e1_the_theme_has_both_modes_with_the_same_keys_and_every_level():
    light, dark = app.THEME["light"], app.THEME["dark"]
    assert set(light) == set(dark) and set(light["levels"]) == set(dark["levels"]) == set(LEVELS)
    assert set(light["band_bg"]) == set(dark["band_bg"]) == {"clean", "alarm", "incomplete", "note"}
    for mode in (light, dark):
        flat = [v for k, v in mode.items() if isinstance(v, str)] + list(mode["levels"].values()) + list(
            mode["band_bg"].values())
        assert all(HEX.fullmatch(c) for c in flat), flat
    assert set(app.LEVEL_WORDS) == set(LEVELS) and all(app.LEVEL_WORDS.values())
    fonts = app.THEME["fonts"]
    assert fonts["ui"] and fonts["mono"] and all(isinstance(f, str) for f in fonts["ui"] + fonts["mono"])
    assert app.THEME["min_size"] == (900, 600)
    assert app.DOCTRINE == "Rules decide; a model may only raise suspicion."


def test_redo_c6_contrast_arithmetic_and_every_level_readable_selected_or_not():
    assert round(app.contrast_ratio("#000000", "#ffffff"), 2) == 21.0
    assert app.contrast_ratio("#777777", "#777777") == 1.0
    assert round(app.contrast_ratio("#ffffff", "#767676"), 2) == 4.54   # the WCAG reference grey
    for mode in ("light", "dark"):
        p = app.THEME[mode]
        grounds = [p["bg"], p["surface"], p["select_bg"]] + list(p["band_bg"].values())
        for level, colour in p["levels"].items():
            for ground in grounds:
                assert app.contrast_ratio(colour, ground) >= 4.5, (mode, level, colour, ground)
        assert app.contrast_ratio(p["select_fg"], p["select_bg"]) >= 4.5
    dark = app.THEME["dark"]
    assert app.contrast_ratio(dark["levels"]["alarm"], dark["select_bg"]) >= 4.5   # the selected red row (C-6)


def test_redo_c1_one_function_for_every_level_exit_3_is_incomplete_never_alarm():
    assert [app.level_of(c) for c in (0, 1, 3, 2)] == ["clean", "alarm", "incomplete", "alarm"]
    assert [app.level_of(None, word=w) for w in ("CLEAN (2 findings suppressed by the overlay)", "ALARM",
                                                 "INCOMPLETE", "what")] == ["clean", "alarm", "incomplete",
                                                                            "incomplete"]
    report = "Raqib watch\nRESULT: INCOMPLETE (exit 3)\n"
    assert app.report_level(3, report) == "incomplete" and app.report_level(None, report) == "incomplete"
    assert app.report_level(1, "") == "alarm" and app.report_level(0, "") == "clean"
    assert app.chip_text(app.report_level(3, report)) == "[incomplete]"
    assert app.code_level(None) == "alarm" and app.code_level(3) == "incomplete"
    src = (ROOT / "raqib" / "app.py").read_text(encoding="utf-8")
    assert '"alarm" if snap["final_exit"] else "clean"' not in src


def test_redo_c3_not_a_clearance_in_every_green_state():
    assert app.chip_text("clean", result=True) == "[clean]. Not a clearance."
    assert app.chip_text(0, 2, result=True) == "[clean] (2 findings suppressed by the overlay). Not a clearance."
    assert app.chip_text("clean") == "[clean]"                      # RULES, DOCTOR: not a watch's result
    assert app.chip_text("alarm", 2, result=True) == "[alarm]"
    word, n = app.report_result("x\nRESULT: CLEAN (2 findings suppressed by the overlay) (exit 0)\n")
    assert (word, n) == ("CLEAN", 2) and app.report_result("RESULT: CLEAN (exit 0)") == ("CLEAN", 0)
    assert app.report_result("no result line") == (None, 0)


def test_redo_c2_each_badge_keeps_its_level_and_its_word_suppressed_red():
    badges = [("clean", "trees now: 0"), ("incomplete", "notifications: off"),
              ("alarm", "1 rule off: NET-TOOL; 2 finding(s) suppressed by the overlay"), ("alarm", "3 holes")]
    items = app.badge_items(badges)
    assert items == [("trees now: 0 [clean]", "clean"), ("notifications: off [incomplete]", "incomplete"),
                     ("1 rule off: NET-TOOL; 2 finding(s) suppressed by the overlay [suppressed]", "suppressed"),
                     ("3 holes [alarm]", "alarm")]
    assert app.level_colour("suppressed") == app.level_colour(1)
    rows = app.badge_rows(badges * 3, width=60)
    assert sum(len(r) for r in rows) == 12 and all(sum(len(t) for t, _ in r) + 3 * (len(r) - 1) <= 60 or len(r) == 1
                                                   for r in rows)


def test_e1_level_colour_follows_the_exit_codes_holes_amber_suppressed_red_notes_grey():
    for mode in ("light", "dark"):
        lv = app.THEME[mode]["levels"]
        assert [app.level_colour(c, mode) for c in (0, 1, 3)] == [lv["clean"], lv["alarm"], lv["incomplete"]]
        assert app.level_colour(2, mode) == lv["alarm"]          # any other code: alarm, as code_level
        assert app.level_colour("hole", mode) == lv["incomplete"]          # holes amber
        assert app.level_colour("suppressed", mode) == lv["alarm"]         # ADR-0008 A-2: red
        assert app.level_colour("note", mode) not in (lv["clean"], lv["alarm"], lv["incomplete"])   # grey
        assert app.level_colour("no such level", mode) == lv["incomplete"]
        assert app.band_colours(1, mode) == (lv["alarm"], app.THEME[mode]["band_bg"]["alarm"])
    assert [app.level_of(c) for c in (0, 1, 3, 2)] == [app.code_level(c) for c in (0, 1, 3, 2)]
    assert app.level_colour(0, "no such mode") == app.THEME["light"]["levels"]["clean"]
    assert [app.level_word(c) for c in (0, 1, 3, "note")] == ["clean", "alarm", "incomplete", "note"]


def is_colour(text):
    """A string Tk would take as a colour: #rgb.. hex, a colour name, a system colour."""
    word = text.strip().lower().replace(" ", "")
    return bool(HEX.fullmatch(text.strip()) or word in TK_NAMES or word in SYSTEM_NAMES
                or re.fullmatch(r"gr[ae]y\d{1,3}", word) or re.fullmatch(r"system[a-z0-9]+", word))


def test_e6_the_colour_name_list_is_tks():
    assert all("gray%d" % n in TK_NAMES and "grey%d" % n in TK_NAMES for n in range(101))
    assert len(TK_NAMES) > 650 and {"crimson", "whitesmoke", "aliceblue", "navajowhite4"} <= TK_NAMES
    assert is_colour("White Smoke") and is_colour("SystemWindowFrame") and is_colour("#b00020") and is_colour("gray7")
    assert not is_colour("clean") and not is_colour("Raqib: idle")


def _formatted_colours(path):
    """(line, option) of every colour option given a value built by string
    formatting (an f-string, %, .format) - a colour that would escape THEME."""
    out = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            if kw.arg not in COLOUR_OPTIONS:
                continue
            for sub in ast.walk(kw.value):
                built = isinstance(sub, ast.JoinedStr) or (
                    isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Mod)) or (
                    isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "format")
                if built:
                    out.append((node.lineno, kw.arg))
    return out


def test_e6_no_colour_built_by_string_formatting():
    assert _formatted_colours(ROOT / "raqib" / "app.py") == []
    assert _formatted_colours(ROOT / "raqib" / "tray.py") == []
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        bad = Path(d) / "bad.py"
        bad.write_text("w.configure(background='#%02x%02x%02x' % (1, 2, 3))\nw.configure(fg=f'#{x}')\n"
                       "s.map('T', foreground=[('a', '{}'.format(c))])\nw.configure(background=THEME['x'])\n",
                       encoding="ascii")
        assert [o for _, o in _formatted_colours(bad)] == ["background", "fg", "foreground"]


def _colour_literals(path):
    """(line, text) of every string constant outside THEME that is a colour."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    skip = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "THEME" for t in node.targets):
            skip |= {id(n) for n in ast.walk(node)}
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip:
            text = node.value.strip()
            if is_colour(text):
                out.append((node.lineno, text))
    return out


def test_e6_the_theme_table_is_the_only_place_a_colour_lives():
    """AST: no colour literal (#rrggbb, or a Tk colour name) outside THEME."""
    assert _colour_literals(ROOT / "raqib" / "app.py") == []
    assert _colour_literals(ROOT / "raqib" / "tray.py") == []
    src = (ROOT / "raqib" / "app.py").read_text(encoding="utf-8")
    assert "LEVEL_COLORS" not in src and src.count("THEME = {") == 1


def test_e1_dark_or_light_from_the_os_where_it_can_be_read_else_light():
    assert app.os_mode("win32", read=lambda: 0) == "dark"
    assert app.os_mode("win32", read=lambda: 1) == "light"

    def broken():
        raise OSError("no such key")
    assert app.os_mode("win32", read=broken) == "light"
    assert app.os_mode("linux") == "light" and app.os_mode("darwin") == "light"
    # the registry is read, never written: winreg only in _apps_use_light_theme, KEY_READ, no Set/Create/Delete
    tree = ast.parse((ROOT / "raqib" / "app.py").read_text(encoding="utf-8"))
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_apps_use_light_theme")
    names = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
    assert {"OpenKey", "QueryValueEx", "KEY_READ", "HKEY_CURRENT_USER"} <= names
    assert not {x for x in names if x.startswith(("Set", "Create", "Delete", "Save", "Load", "Flush"))}
    winreg_users = {f.name for f in ast.walk(tree) if isinstance(f, ast.FunctionDef)
                    for n in ast.walk(f) if isinstance(n, ast.Import) and any(a.name == "winreg" for a in n.names)}
    assert winreg_users == {"_apps_use_light_theme"}


def test_e1_named_system_fonts_with_fallbacks():
    assert app.pick_font(("Segoe UI", "DejaVu Sans"), ["dejavu sans", "Courier"]) == "dejavu sans"
    assert app.pick_font(("Segoe UI",), ["Segoe UI"]) == "Segoe UI"
    assert app.pick_font(("Nothing",), ["Courier"]) is None   # Tk's own default font stays


# --- E2: the host table ---------------------------------------------------------------------------------------

def test_e2_the_tree_table_has_the_eight_columns_in_order():
    assert [c[1] for c in app.TREE_COLUMNS] == ["image", "pid", "kind", "source", "findings", "rhythm / suspicion",
                                                "first seen", "endpoints"]
    names = [n for n, _ in app.HOST_COLUMNS]
    for cid, heading, width, index, kind in app.TREE_COLUMNS:   # each maps to its host_rows cell
        assert names[index] == {"kind": "named"}.get(heading, heading)
        assert width > 0 and kind in ("text", "number", "severity")
    assert sum(c[2] for c in app.TREE_COLUMNS) <= 860 and sum(c[2] for c in app.RULES_COLUMNS) <= 860
    row = ("img", "7", "named (new)", "2026-11-09T00:00:00Z", "3", "os", "high 1", "-", "1.2.3.4:443")
    assert app.tree_values(row) == ("img", "7", "named (new)", "os", "high 1", "-", "2026-11-09T00:00:00Z",
                                    "1.2.3.4:443")


def test_e2_sort_keys_numbers_severities_text_and_dash_last():
    k = app.sort_key
    assert sorted(["10", "9", "x", "100"], key=lambda c: k("number", c)) == ["9", "10", "100", "x"]
    cells = ["none", "medium 2", "high 1, low 4", "high 2", "low 1", "-", "history 3"]
    assert sorted(cells, key=lambda c: k("severity", c)) == ["high 2", "high 1, low 4", "medium 2", "low 1",
                                                             "history 3", "none", "-"]
    assert sorted(["high", "low", "medium"], key=lambda c: k("severity", c)) == ["high", "medium", "low"]
    assert sorted(["b", "-", "A", "a10", "a9"], key=lambda c: k("text", c)) == ["A", "a9", "a10", "b", "-"]
    rows = [("z", "10"), ("a", "9"), ("m", "100")]
    cols = (("image", "image", 1, 0, "text"), ("pid", "pid", 1, 1, "number"))
    assert [r[0] for r in app.sort_rows(rows, cols, "pid")] == ["a", "z", "m"]
    assert [r[0] for r in app.sort_rows(rows, cols, "pid", reverse=True)] == ["m", "z", "a"]
    assert [r[0] for r in app.sort_rows(rows, cols, "image")] == ["a", "m", "z"]


def test_redo_c7_dash_last_both_ways_stable_and_ids_that_do_not_move():
    cols = (("image", "image", 1, 0, "text"), ("pid", "pid", 1, 1, "number"), ("f", "findings", 1, 2, "severity"))
    rows = [("b", "-", "none"), ("a", "9", "high 1"), ("-", "10", "-"), ("c", "x", "low 2"), ("d", "2", "medium 1")]
    for reverse in (False, True):
        assert [r[0] for r in app.sort_rows(rows, cols, "image", reverse)][-1] == "-"
        assert [r[1] for r in app.sort_rows(rows, cols, "pid", reverse)][-2:] == ["-", "x"]
        assert [r[2] for r in app.sort_rows(rows, cols, "f", reverse)][-2:] == ["none", "-"]
    assert [r[1] for r in app.sort_rows(rows, cols, "pid", True)][:3] == ["10", "9", "2"]
    same = [("a", "1", "x"), ("a", "1", "y")]
    assert [r[2] for r in app.sort_rows(same, cols, "pid", True)] == ["x", "y"]          # stable reversed
    items = [(("x", "1"), "p"), (("x", "1"), "q")]
    assert [r[1] for r in app.sort_rows(items, cols, "image", get=lambda it: it[0])] == ["p", "q"]
    ids = app.table_iids([("img", "7"), ("img", "7"), ("other", "8")])
    assert ids == ["img|7", "img|7+1", "other|8"] and app.table_iids([("img", "7")]) == ["img|7"]
    src = (ROOT / "raqib" / "app.py").read_text(encoding="utf-8")
    fill = src.split("    def _fill(self, key, tree, items, columns):", 1)[1].split("\n    def ", 1)[0]
    assert "sort_rows(" in fill and "table_iids(" in fill and "sort_key(" not in fill


def test_e2_row_levels_say_it_in_words_too():
    base = ["img", "1", "named", "-", "0", "-", "none", "-", "-"]
    assert app.row_level(base) is None
    assert app.row_level(base[:2] + ["unknown (new)"] + base[3:]) == "alarm"
    assert app.row_level(base[:6] + ["medium 1"] + base[7:]) == "alarm"
    assert app.row_level(base[:2] + ["named (history, gone)"] + base[3:]) == "note"
    assert app.row_level(base[:2] + ["unknown"] + base[3:]) is None      # "unknown" is not "new"


def _host_state():
    st = FakeHostWatch().state(0)
    key = [4242, "scribe", "2026-11-09T00:00:00Z"]
    other = [7, "claude", None]
    word = host.tree_word(tuple(key))
    tree = {"key": key, "pid": 4242, "image": "scribe", "exe": "/usr/local/bin/scribe", "started": key[2],
            "class": "candidate", "named": False, "benign": False, "acts": 2, "knocked": True,
            "endpoints": ["1.2.3.4:443"], "cites": [{"src": "proc", "line": 12, "text": "scribe --session secret"}]}
    st["host"] = dict(st["host"], now=2, new=1, trees=[tree, dict(tree, key=other, pid=7, image="claude",
                                                                  named=True, knocked=False, cites=[])],
                      findings=[{"rule_id": "NEW-AGENT-UNKNOWN", "severity": "medium", "round": 1, "tree": word,
                                 "tree_key": key, "summary": "a new tree", "notice": "sent", "run": "r1",
                                 "cited_seq": [3]},
                                {"rule_id": "NEW-AGENT", "severity": "high", "round": 1, "tree": "7:claude:-",
                                 "tree_key": other, "summary": "claude", "notice": "sent", "run": "r1",
                                 "cited_seq": [4]}],
                      suspicions=[{"suspicion": 0.9, "round": 2, "tree": word, "reasons": ["odd"], "notice": "sent",
                                   "backend": "fake", "model": "m", "trace": "t", "cited_seq": [5]}],
                      dark_notes=[{"text": "round 3: a note of scribe", "live_tree": word},
                                  {"text": "round 3: a note of another", "live_tree": "9:x:-"}])
    return st


def test_e2_the_detail_pane_shows_the_selected_trees_findings_notes_source_cites():
    v = app.host_watch_view(_host_state())
    assert len(v["details"]) == len(v["rows"]) == 2
    text = app.tree_detail_text(v["rows"][0], v["details"][0])
    assert text.startswith("scribe pid 4242: unknown (new)")
    assert "NEW-AGENT-UNKNOWN [medium]" in text and "SUSPECT [suspicion 0.90]" in text
    assert "NEW-AGENT [high]" not in text
    assert "round 3: a note of scribe" in text and "a note of another" not in text
    assert "cites: proc:12" in text and "acts 2" in text and "source: " in text and "class candidate" in text
    assert "--session" not in text and "/usr/local/bin" not in text    # never a command line or an exe path
    other = app.tree_detail_text(v["rows"][1], v["details"][1])
    assert "NEW-AGENT [high]" in other and "FINDINGS: 1" in other and "cites: -" in other
    assert "FINDINGS: 0" in app.tree_detail_text(("x", "1"))            # a row without its detail still says


def test_e2_the_look_has_details_too_and_look_json_is_unchanged(home):
    p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0, home=str(home)).start()
    assert until(p.done, WAIT)
    v = p.view()
    assert len(v["details"]) == len(v["rows"]) == 2
    import json
    written = json.loads(Path(app.look_path(str(home))).read_text(encoding="ascii"))
    assert "details" not in written and written["rows"] == [list(r) for r in v["rows"]]
    # the text under the table: no table there any more (the Treeview has the rows), the rest as host_body
    body = app.host_text_body(v)
    assert app.host_table(v["rows"])[0] not in body and body == app.host_body(dict(v, rows=[])).lstrip("\n")
    assert "HOLES (A3): 14" in body


def test_e2_the_empty_state_and_nothing_read_keep_not_a_clearance():
    i = dict(inv("linux"), candidates=[], act_roots=[], footprints=[], agent_dark=[], result="clean")
    p, _ = probe(lambda: i)
    assert until(p.done, WAIT)
    body = app.host_text_body(p.view())
    assert body.startswith("no agent seen (") and "Not a clearance." in body
    p, _ = probe(lambda: dict(i, records=0))
    assert until(p.done, WAIT)
    v = p.view()
    assert v["word"] == "NOTHING READ" and "Not a clearance." in app.host_text_body(v)


# --- E3: the Rules table, the header ---------------------------------------------------------------------------

def test_e3_the_rules_table_says_the_overlay_state_per_row(home):
    overlay.set_status("NET-TOOL", "off", str(home))
    overlay.set_threshold("HOST-RHYTHM", "w", "20", str(home))   # M7.6c REDO E-3: suspect_every is no threshold
    rows = dict((v[0], (v, level)) for v, level in app.rules_rows(overlay.listing(overlay.load(str(home)))))
    assert [c[0] for c in app.RULES_COLUMNS] == ["id", "kind", "class", "severity", "budget", "status", "overlay",
                                                 "origin", "thresholds"]
    assert rows["NET-TOOL"][0][5:7] == ("off", "off by the overlay") and rows["NET-TOOL"][1] == "incomplete"
    assert rows["HOST-RHYTHM"][0][6] == "thresholds set" and "w=20*" in rows["HOST-RHYTHM"][0][8]
    assert rows["SECRET-OUTPUT"][0][5:7] == ("on", "-") and rows["SECRET-OUTPUT"][1] is None
    yaml_off = app.rules_rows([{"id": "X", "status": "off", "off_by": "yaml", "thresholds": []}])
    assert yaml_off[0][0][6] == "off in its YAML" and yaml_off[0][0][8] == "-"


def test_e3_the_header_rules_item_is_red_while_suppressed():
    suppressed = {"rules_overlay": {"not_judged": {"NET-TOOL": {"fired": 2}}}}
    assert app.header_rules("1 rule off: NET-TOOL", [suppressed, None]) == (
        "1 rule off: NET-TOOL; 2 finding(s) suppressed by the overlay", "suppressed")
    assert app.header_rules("1 rule off: NET-TOOL", [{}]) == ("1 rule off: NET-TOOL", "incomplete")
    assert app.header_rules("no rule off") == ("no rule off", None)
    assert app.level_colour("suppressed") == app.level_colour(1)


def test_e3_the_rules_text_under_the_table_has_no_table(home):
    p = app.RulesPanel(home=str(home))
    assert p.notes_text().startswith(app.RULES_INTRO) and "rules: no rule off" in p.notes_text()
    assert overlay.table_text(p.rows).splitlines()[0] not in p.notes_text()
    assert overlay.table_text(p.rows).splitlines()[0] in p.text()        # text() as before (raqib rules, tests)


def test_e1_text_tags_colour_findings_holes_notes_with_their_words():
    tags = dict(app.text_tags("FINDINGS: 2\n  high (1)\n    X\n\nNOTES (not alarms): 1\n  - n\n\nHOLES (A3): 1\n"
                              "  - h\nhole: tray\nRESULT: CLEAN (exit 0)\n"))
    assert tags["FINDINGS: 2"] == tags["    X"] == "alarm" and tags["  - n"] == "note"
    assert tags["  - h"] == tags["hole: tray"] == "hole" and tags["RESULT: CLEAN (exit 0)"] is None
    assert dict(app.text_tags("FINDINGS: 0\nHOLES (A3): 0\n")) == {"FINDINGS: 0": None, "HOLES (A3): 0": None}


# --- E4: the first run and the doctrine ---------------------------------------------------------------------

def test_e4_the_first_run_text_appears_and_then_does_not(home):
    lines = app.first_run_lines(str(home))
    assert len(lines) == 3 and lines == list(app.FIRST_RUN)
    assert "what Raqib sees" in lines[0] and "never touches an agent" in lines[1]
    assert "\"No agent seen\" is never a clearance" in lines[2]
    assert app.look_path(str(home)) == os.path.join(str(home), ".raqib", "host", "look.json")
    p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0, home=str(home)).start()   # the first look writes it
    assert until(p.done, WAIT)
    p.view()
    assert app.first_run_lines(str(home)) == []
    assert app.first_run_lines(None, exists=lambda path: False) == list(app.FIRST_RUN)


def test_redo_c5_the_footer_keeps_each_of_the_looks_holes_three_shown_n_more():
    lines = app.foot_lines(["tray: x"], ["page: y"], ["round at open: a", "round at open: b", "round at open: c"])
    assert lines == ["hole: tray: x", "hole: round at open: a", "hole: round at open: b", "hole: round at open: c",
                     "note: page: y"]
    assert app.foot_more(lines) == "(2 more)" and app.FOOT_LINES == 3 and app.foot_more(lines[:3]) == ""
    assert app.foot_lines([], [], []) == []


# --- E5: the tray tip ---------------------------------------------------------------------------------------

def test_redo_c4_the_tray_tip_host_project_only_idle_suspicions_apart(tmp_path):
    assert tray.tip_text(3, 1, 4) == "Raqib: 3 trees, 1 new, 4 findings" and tray.IDLE_TIP == "Raqib: idle"
    assert tray.tip_text(3, 1, 4, 2) == "Raqib: 3 trees, 1 new, 4 findings +2 suspicions"
    assert tray.Tray(lambda a: None, platform="linux").tip == "Raqib: idle"
    c = app.Controller(None, make_session=FakeSession, make_host=lambda: FakeSession("host"))
    assert c.tip == "Raqib: idle" and c.host_tip(5, 2, 1, 0, 9) == "Raqib: idle"
    proj = tmp_path / "myproj"
    proj.mkdir()
    c.start(str(proj))                            # a project watch alone: its name and its findings, no trees
    assert c.host_tip(5, 2, 1, 0, 9) == "Raqib: project myproj, 9 findings"
    c.start_host()                                # the host watched: the host watch's tip
    assert c.host_tip(5, 2, 3, 1, 9) == "Raqib: 5 trees, 2 new, 3 findings +1 suspicions"
    c.stop("x")
    assert c.host_tip(5, 2, 3) == "Raqib: idle"
    assert len(tray.tip_text(10 ** 6, 10 ** 6, 10 ** 6, 10 ** 6)) <= 127
    assert len(tray.project_tip("p" * 300, 10 ** 6)) == 127 and tray.project_tip("p" * 300, 1).endswith(", 1 findings")
    v = app.host_watch_view(_host_state())
    assert v["suspicions"] == 1 and len(v["findings"]) == 3      # 2 findings + 1 suspicion line, counted apart


# --- E6: the A4 guards still hold ---------------------------------------------------------------------------

def test_e6_no_new_writes_in_app_py():
    """The only writes of app.py stay where they were: the look (HostProbe._write,
    ~/.raqib/host/look.json) and app.log (AppLog); the theme reads only."""
    tree = ast.parse((ROOT / "raqib" / "app.py").read_text(encoding="utf-8"))
    writers = set()
    for cls in [n for n in tree.body if isinstance(n, ast.ClassDef)] + [tree]:
        for fn in (n for n in ast.walk(cls) if isinstance(n, ast.FunctionDef)):
            for sub in ast.walk(fn):
                if isinstance(sub, ast.Call):
                    f = sub.func
                    name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                    if name in ("open", "makedirs", "write_json", "replace", "rename", "remove", "unlink", "mkstemp",
                                "copy", "copyfile", "SetValueEx", "CreateKey"):
                        writers.add(fn.name)
    assert writers == {"_write", "__init__"}, writers
    src = (ROOT / "raqib" / "app.py").read_text(encoding="utf-8")
    assert src.count("open(path, \"w\"") == 1 and "hostmod.write_json(self.path(), record)" in src


def test_e6_files_are_ascii():
    for name in ("raqib/app.py", "raqib/tray.py", "tests/test_app_look.py"):
        (ROOT / name).read_bytes().decode("ascii")


def test_e6_readme_the_windows_three_lines_refreshed():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    section = text.split("## The window\n", 1)[1].split("\n## ", 1)[0]
    lines = [line for line in section.split("\n") if line.strip()]
    assert len(lines) == 5
    assert "Host | Project | Rules | Log" in lines[2] and "Rules decide; a model may only raise suspicion." in lines[3]
    assert "Raqib: N trees, K new, F findings" in " ".join(lines)


# --- the Tk window at 900x600 -------------------------------------------------------------------------------

def _fits(root, width=900, height=600):
    root.update_idletasks()
    return root.winfo_reqwidth() <= width and root.winfo_reqheight() <= height, (root.winfo_reqwidth(),
                                                                                    root.winfo_reqheight())


def test_tk_every_screen_fits_900x600_with_its_widgets(home, tmp_path):
    tkinter, root = tk_or_skip()
    window = None
    try:
        from tkinter import ttk
        p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0)           # no home: look.json is not written
        c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=TkSession,
                           make_host=lambda: TkHost())
        doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, [("hooks", (False, "not installed"))], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p,
                            home=str(home))
        root.withdraw()
        root.geometry("900x600")
        assert until(lambda: doctor.result() is not None and p.done(), 10)
        window.tick()
        # E4: the first-run lines (no look.json under this home) and the doctrine
        assert window.first_run_shown and window.first_run_label.cget("text") == "\n".join(app.FIRST_RUN)
        assert window.doctrine.cget("text") == app.DOCTRINE
        # E2: the Treeview with the eight columns, sortable; the detail pane follows the selection
        assert isinstance(window.host_tree, ttk.Treeview)
        assert list(window.host_tree.cget("columns")) == [col[0] for col in app.TREE_COLUMNS]
        kids = window.host_tree.get_children()
        assert len(kids) == 2 and window.band.cget("text") == "HOST: 2 TREE(S)"
        assert window.band_level.cget("text") == "[alarm]"
        window.sort_by("host", "pid")
        pids = [window.host_tree.item(i, "values")[1] for i in window.host_tree.get_children()]
        assert pids == sorted(pids, key=int) and window.host_tree.heading("pid", "text") == "pid ^"
        window.sort_by("host", "pid")
        assert [window.host_tree.item(i, "values")[1] for i in window.host_tree.get_children()] == pids[::-1]
        window.host_tree.selection_set(window.host_tree.get_children()[0])
        window._show_tree_detail()
        assert window.host_detail.get("1.0", "end").startswith(window.host_tree.item(
            window.host_tree.get_children()[0], "values")[0])
        # REDO C-7: the selection survives a sort and a refresh (the rows rebuilt)
        picked = window.host_tree.selection()
        window.sort_by("host", "image")
        window.shown.pop("table:host", None)
        window.tick()
        assert window.host_tree.selection() == picked
        # REDO C-5: each of the look's holes stands in the footer, three lines shown, "(N more)"
        look = ["hole: round at open: %s" % h for h in p.view()["holes"]]
        assert all(x in window.foot_text().split("\n") for x in look) and len(look) == 14
        assert window.foot_more.cget("text") == "(%d more)" % (len(look) - 3) and int(window.foot.cget("height")) == 3
        fits = []
        fits.append(("host", _fits(root)))
        window.toggle_screen_log()                                     # the header's Log on the host screen
        assert window.log_tab.cget("text") == "Hide log"
        fits.append(("host with its log", _fits(root)))
        window.toggle_screen_log()
        window.host_toggle()                                           # the host watched: its badges rows
        window.tick()
        assert window.band.cget("text") == "WATCHING HOST" and window.host_badges.winfo_children()
        fits.append(("host watching", _fits(root)))
        window.host_toggle()                                           # its final report
        window.tick()
        fits.append(("host finished", _fits(root)))
        window.show_first()
        window.tick()
        assert str(window.doctor_text.cget("font")) == "TkFixedFont"
        fits.append(("project", _fits(root)))
        window.start()
        window.tick()
        window.toggle_log()
        assert str(window.log_text.cget("font")) == "TkFixedFont"     # E3: the log monospace
        fits.append(("watching with its log", _fits(root)))
        window.toggle_log()
        window.show_rules()
        window.tick()
        assert isinstance(window.rules_tree, ttk.Treeview) and len(window.rules_tree.get_children()) >= 10
        assert list(window.rules_tree.cget("columns"))[6] == "overlay"
        fits.append(("rules", _fits(root)))
        assert all(ok for _, (ok, _) in fits), fits
        # E4: the look is written (here, by hand, as the look does): the first-run lines go
        os.makedirs(os.path.dirname(app.look_path(str(home))), exist_ok=True)
        Path(app.look_path(str(home))).write_text("{}", encoding="ascii")
        window.tick()
        assert not window.first_run_shown and not window.first_run_label.winfo_manager()
        assert window.running_note.cget("text").startswith("running: ")
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


class LookSession(TkSession):
    """A project watch whose state and report the test sets."""

    def __init__(self, project):
        super().__init__(project)
        self.st, self.code = None, None

    def snapshot(self):
        return dict(super().snapshot(), final_exit=self.code if self.final_text else None)

    def state(self):
        return self.st or super().state()


def test_tk_redo_dark_mode_bands_badges_and_every_screen(home, tmp_path, monkeypatch):
    """REDO C-1, C-2, C-3, C-6: in dark mode, every screen once; exit 3 is
    "[incomplete]" in amber; FINISHED exit 0 with suppressed findings says
    it and "Not a clearance."; WATCHING clean says "Not a clearance."; each
    badge its own label in its level's style, the suppressed one red."""
    tkinter, root = tk_or_skip()
    window = None
    monkeypatch.setattr(app, "os_mode", lambda platform=None, read=None: "dark")
    dark = app.THEME["dark"]["levels"]
    try:
        p = app.HostProbe(lambda: inv("linux"), CATALOG, 20.0)
        c = app.Controller(app.Options(None, None, 60, environ={}), tray=None, make_session=LookSession,
                           make_host=lambda: TkHost())
        doctor = app.DoctorJob(str(tmp_path), checks=lambda x: (x, [("python", (True, "3"))], []))
        window = app.Window(tkinter, root, c, str(tmp_path), doctor_job=lambda x: doctor, probe=lambda: p,
                            home=str(home))
        root.withdraw()
        assert window.mode == "dark" and str(window.host_text.cget("background")) == app.THEME["dark"]["surface"]
        assert until(lambda: doctor.result() is not None and p.done(), 10)
        window.tick()
        assert str(window.band_level.cget("foreground")) == dark["alarm"]
        window.show_rules()
        window.tick()
        window.show_first()
        window.tick()
        window.start()
        st = dict(TkSession("x").state(), rules_overlay={"off": [{"rule_id": "NET-TOOL"}],
                                                          "not_judged": {"NET-TOOL": {"fired": 2}}})
        c.session.st = st
        window.tick()
        assert window.band.cget("text") == "WATCHING"
        assert window.band_level.cget("text") == "[clean] (2 findings suppressed by the overlay). Not a clearance."
        labels = [w for line in window.badges.winfo_children() for w in line.winfo_children()]
        assert labels and all(str(w.cget("text")).endswith("]") for w in labels)
        red = [w for w in labels if "suppressed by the overlay" in str(w.cget("text"))]
        assert len(red) == 1 and str(red[0].cget("style")) == "suppressed.Level.TLabel"
        style = tkinter.ttk.Style(root)
        assert str(style.lookup("suppressed.Level.TLabel", "foreground")) == dark["suppressed"]
        c.session.phase, c.session.code = "finished", 3
        c.session.final_text = "Raqib watch\nRESULT: INCOMPLETE (exit 3)\n"
        window.tick()
        assert window.band.cget("text") == "FINISHED" and window.band_level.cget("text") == "[incomplete]"
        assert str(window.band_level.cget("foreground")) == dark["incomplete"]
        c.session.final_text = "RESULT: CLEAN (2 findings suppressed by the overlay) (exit 0)\n"
        c.session.code = 0
        window.tick()
        assert window.band_level.cget("text") == "[clean] (2 findings suppressed by the overlay). Not a clearance."
        window.show_host()
        window.tick()
        assert _fits(root)[0]
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()
