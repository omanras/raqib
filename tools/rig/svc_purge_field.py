"""Probe only (never merged): the nineteenth measurement's reader - what the place of Raqib's Windows service is
after the service is removed, as an administrator reads it, and whether an administrator's process removes it.
    svc_purge_field.py read PLACE      the name's attributes, owner and list (through the runner's own reader), and
                                       what is in it: how many folders and files, how many bytes
    svc_purge_field.py remove PLACE    removes what is in it, bottom up, never through a link, then the place;
                                       counts what was removed and each error of the system by its number
It prints numbers, Raqib's own file names at the top level, and the list with users' SIDs masked."""
import collections
import os
import re
import stat
import sys
import time

from raqib import winservice


def masked(text):
    return re.sub(r"S-1-5-21-[0-9-]+", "S-1-5-21-<a user>", str(text))


def read(place):
    try:
        attrs, sddl = winservice.System().read_place(place)
        print("the name: attributes 0x%x (folder %s, link or other reparse point %s); %s" % (
            attrs, bool(attrs & 0x10), bool(attrs & 0x400), masked(sddl)))
    except OSError as exc:
        print("the name was not read: error %s (%s)" % (exc.errno, masked(exc.strerror)))
        return
    folders = files = size = links = 0
    for root, dirs, names in os.walk(place):
        folders += len(dirs)
        for name in names:
            files += 1
            try:
                st = os.lstat(os.path.join(root, name))
                size += st.st_size
                links += bool(getattr(st, "st_file_attributes", 0) & 0x400)
            except OSError:
                pass
    try:
        top = sorted(os.listdir(place))
    except OSError as exc:
        top = ["not listed: error %s" % exc.winerror]
    print("in it: %d folders, %d files, %d bytes, %d reparse points; at its top: %s" % (
        folders, files, size, links, ", ".join(top)[:300]))


def remove(place):
    began = time.monotonic()
    gone, errors = 0, collections.Counter()
    for root, dirs, names in os.walk(place, topdown=False):
        for name in names:
            try:
                os.unlink(os.path.join(root, name))
                gone += 1
            except OSError as exc:
                errors[exc.winerror] += 1
        for name in dirs:
            path = os.path.join(root, name)
            try:
                st = os.lstat(path)
                if getattr(st, "st_file_attributes", 0) & 0x400 or stat.S_ISLNK(st.st_mode):
                    errors["a link, not entered and not removed"] += 1
                    continue
                os.rmdir(path)
                gone += 1
            except OSError as exc:
                errors[exc.winerror] += 1
    try:
        os.rmdir(place)
        last = "the place itself removed"
    except OSError as exc:
        last = "the place itself not removed: error %s" % exc.winerror
    print("removed %d names in %.2f s; errors by the system's number: %s; %s; there now: %s" % (
        gone, time.monotonic() - began, dict(errors) or "none", last, os.path.lexists(place)))


if __name__ == "__main__":
    {"read": read, "remove": remove}[sys.argv[1]](sys.argv[2])
