"""Probe only (never merged): is the window's Link tab on the screen on Windows? The commander updated to 0.8.0 on a
Windows machine (Python 3.12, ARM64) and sees no Link in the window; in the code the tab is made on every platform.
This opens the real window as `raqib app` does (the same code path: cli.main(["app"])), lets Tk lay it out, and says
of each of the rail's tabs whether it is mapped and where it is, at the size the window opens with and at its
smallest; then it closes the window. It watches nothing and changes nothing."""
import sys
import time
import tkinter

from raqib import app, cli

seen = []


class Probed(app.Window):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        seen.append(self)


def say(root, w, label):
    for _ in range(5):
        root.update()
        time.sleep(0.1)
    rail = w.rail
    print("%s: window %s; the screen %dx%d; scale %.2f (%.1f dots an inch); the rail %dx%d" % (
        label, root.wm_geometry(), root.winfo_screenwidth(), root.winfo_screenheight(), w.scale,
        root.winfo_fpixels("1i"), rail.winfo_width(), rail.winfo_height()))
    for tab in (w.host_tab, w.project_tab, w.rules_tab, w.log_tab, w.link_tab):
        bottom = tab.winfo_y() + tab.winfo_height()
        print("  tab %-8s mapped %s viewable %s; y %d to %d of the rail's %d; %s" % (
            tab.cget("text"), bool(tab.winfo_ismapped()), bool(tab.winfo_viewable()), tab.winfo_y(), bottom,
            rail.winfo_height(), "on the screen" if tab.winfo_ismapped() and bottom <= rail.winfo_height()
            else "NOT WHOLE ON THE SCREEN"))
    for name in ("doctrine", "rules_note", "running_note", "rail_watches", "page_slot"):
        x = getattr(w, name, None)
        if x is not None:
            print("  %-13s mapped %s; y %d, height %d" % (name, bool(x.winfo_ismapped()), x.winfo_y(), x.winfo_height()))


class Tk(tkinter.Tk):
    def mainloop(self, n=0):
        w = seen[0]
        print("title: %r; platform %s; python %s; tk %s" % (self.title(), sys.platform, sys.version.split()[0],
                                                           self.tk.call("info", "patchlevel")))
        say(self, w, "as it opens")
        mw, mh = self.minsize()
        self.geometry("%dx%d" % (mw, mh))
        say(self, w, "at its smallest (%dx%d)" % (mw, mh))
        w.show_link()
        say(self, w, "on the Link screen")
        print("the screen shown: %r" % (w.screen,))


def main():
    app.Window = Probed
    tkinter.Tk = Tk
    code = cli.main(["app"])
    print("raqib app's exit: %s" % code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
