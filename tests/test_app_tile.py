"""M8.4 (the third field run, 2026-11-11): on the commander's Windows the window stayed white and did not answer;
its main thread was in Tk's first idle pass (Window.__init__ -> _title_bar -> update_idletasks) thirty seconds on.
ttk does not scale an image element's middle, it tiles it, one blit per tile, and every card, table, field and
button was a picture whose middle was two pixels. Each stretched picture now has a middle of THEME's tile, built
by Tk's own photo copy, so a redraw is a few dozen blits; and the painter decides a pixel the arc does not cross
without sampling it. The look is what it was: the same pixels in the corners, the same colour in the middle."""
import math
import random

from raqib import app

import test_app_redo as T
from test_app_redo import home, tk_or_skip   # noqa: F401  (the window tests' own fixtures)


def sampled(px, py, x0, y0, x1, y1, r, n=4):
    """The painter's coverage as M8.1 computed it: every pixel on an edge sampled 16 times."""
    if px + 1 <= x0 or py + 1 <= y0 or px >= x1 or py >= y1:
        return 0.0
    inside = px >= x0 and py >= y0 and px + 1 <= x1 and py + 1 <= y1
    if inside and (x0 + r <= px and px + 1 <= x1 - r or y0 + r <= py and py + 1 <= y1 - r):
        return 1.0
    hit = 0
    for i in range(n):
        sx = px + (i + 0.5) / n
        for j in range(n):
            sy = py + (j + 0.5) / n
            if x0 <= sx <= x1 and y0 <= sy <= y1:
                cx, cy = min(max(sx, x0 + r), x1 - r), min(max(sy, y0 + r), y1 - r)
                hit += (sx - cx) ** 2 + (sy - cy) ** 2 <= r * r
    return hit / float(n * n)


def test_the_painter_gives_every_pixel_the_value_the_samples_gave():
    """Must not touch: the look. Over boxes of whole and fractional edges and every kind of radius (none, small,
    half a side, more than half a side), each pixel's coverage is exactly what sampling it gave."""
    rnd = random.Random(7)
    compared = 0
    for _ in range(400):
        w, h = rnd.randint(4, 48), rnd.randint(4, 48)
        f = rnd.choice([0, 0, 0.5, 0.75, 1.25, 1.5, 2, 3])
        r = rnd.choice([0, 1, 2, 3, 4.5, 6, 7.5, 10, 12, 15, 18, 24, min(w, h) / 2.0, rnd.uniform(0, min(w, h))])
        box = (f, f, w - f, h - f, r)
        for py in range(-1, h + 1):
            for px in range(-1, w + 1):
                compared += 1
                assert app._cover_rect(px, py, *box) == sampled(px, py, *box), (px, py, box)
    assert compared > 250000


def test_a_pixel_the_arc_does_not_cross_is_not_sampled(monkeypatch):
    """For: the cost. A 40 x 40 box of radius 12 has 4 x 144 corner pixels; only those the arc crosses, and the
    partly covered ones on a fractional edge, may reach the sampling loop (counted by the range() calls)."""
    calls = []
    real_range = range

    def counting(*a):
        calls.append(a)
        return real_range(*a)
    monkeypatch.setattr(app, "range", counting, raising=False)
    for py in real_range(40):
        for px in real_range(40):
            app._cover_rect(px, py, 0, 0, 40, 40, 12)
    monkeypatch.undo()
    outer = [a for a in calls if a == (4,)]
    sampled_pixels = len(outer) / 5.0   # one outer loop and four inner ones a sampled pixel
    assert 0 < sampled_pixels <= 4 * 30, sampled_pixels   # the arcs' own pixels, not the 576 of the four corners


def _pixels(img, x0, y0, x1, y1):
    return [[tuple(img.get(x, y)) for x in range(x0, x1)] for y in range(y0, y1)]


def test_tk_every_stretched_picture_has_a_middle_a_redraw_can_afford(home, tmp_path):   # noqa: F811
    """For: the white window. Every image element with a border is given pictures whose middle, in each
    direction it has one, is THEME's tile wide - so the cards, the table and the fields of a 1100 x 720 window
    are tiled in dozens of blits, not in the hundreds of thousands a two-pixel middle took."""
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = T._window(tkinter, root, home, tmp_path)
        tile = window.px(app.THEME["px"]["tile"])
        assert tile >= 48 and set(window.elements) >= {"Card.box", "Table.box", "Field.box", "TButton.box"}
        stretched = 0
        for name, (border, pictures, asked) in sorted(window.elements.items()):
            for img in pictures:
                for size in (img.width(), img.height()):
                    middle = size - 2 * border if border else 0
                    if border and middle > 0:
                        stretched += 1
                        assert middle >= tile, (name, size, border)
        assert stretched >= 40
        w, h = app.THEME["size"]
        border, pictures, _ = window.elements["Card.box"]
        blits = math.ceil(w / float(pictures[0].width() - 2 * border)) * math.ceil(
            h / float(pictures[0].height() - 2 * border))
        assert blits <= 300, blits   # the whole window as one card; a two-pixel middle made it 198,000
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()


def test_tk_a_widened_picture_is_the_same_picture(home, tmp_path):   # noqa: F811
    """Must not touch: the look. The card's widened picture has the small one's corners pixel for pixel, its
    edges repeated along the middle, and the small one's middle colour all through its own; an element without
    a border (the switch, the chevron) is given the picture as it was drawn."""
    tkinter, root = tk_or_skip()
    window = None
    try:
        window, c = T._window(tkinter, root, home, tmp_path)
        small = window.images[("card",)]
        border, (wide,), asked = window.elements["Card.box"]
        assert asked == (small.width(), small.height())   # the element asks the drawn picture's room, no more
        tile = window.px(app.THEME["px"]["tile"])
        n, b = small.width(), border
        assert small.height() == n and 0 < n - 2 * b < tile
        assert (wide.width(), wide.height()) == (2 * b + tile, 2 * b + tile)
        W = wide.width()
        for (sx, sy), (dx, dy) in (((0, 0), (0, 0)), ((n - b, 0), (W - b, 0)), ((0, n - b), (0, W - b)),
                                   ((n - b, n - b), (W - b, W - b))):
            assert _pixels(small, sx, sy, sx + b, sy + b) == _pixels(wide, dx, dy, dx + b, dy + b), (sx, sy)
        middle = tuple(small.get(b, b))
        for x in range(b, W - b, 7):
            assert [tuple(wide.get(x, y)) for y in range(b)] == [tuple(small.get(b, y)) for y in range(b)]   # top edge
            assert [tuple(wide.get(y, x)) for y in range(b)] == [tuple(small.get(y, b)) for y in range(b)]   # left edge
            for y in range(b, W - b, 7):
                assert tuple(wide.get(x, y)) == middle, (x, y)
        # a small widget keeps its size: a button is as tall as its text and padding ask, not as its tile
        from tkinter import ttk
        button = ttk.Button(root, text="Stop", style="TButton")
        pill = ttk.Label(root, text="alarm", style=window._pill_style("alarm"))
        root.update_idletasks()
        assert 0 < button.winfo_reqheight() < tile and 0 < pill.winfo_reqheight() < tile // 2 + 12, (
            button.winfo_reqheight(), pill.winfo_reqheight(), tile)
        button.destroy()
        pill.destroy()
        for name in ("Switch.indicator", "Disclosure.indicator"):
            border, pictures, _ = window.elements[name]
            assert border == 0 and all(img in window.images.values() for img in pictures)
            assert not [k for k in window.images if k[0] == "wide" and window.images[k] in pictures], name
    finally:
        if window is not None:
            window.destroy()
        else:
            root.destroy()
