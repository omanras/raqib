# Field note: first blind `raqib discover` on a Windows host running Kimi (2026-11-02)

main 8991239 (M5.0 merged), Windows 10 Pro 19045, Python 3.14 (outside the
CI matrix), exported texts (no Sysmon), catalog copy without the `.kimi`
footprint (B-10). Kimi was mid-task: the commander asked it to run
`ping -n 90 127.0.0.1`, and the exports were taken during the 90 s.

Result: ALARM, exit 1, complete; 2 candidates; the Kimi process was NOT a
candidate root. What the tree looked like (from win-process.csv, read by
the Table):

    explorer 6636  (talks: 82.178.158.113:443 ESTABLISHED)
      cmd 13236
        kimi.exe 10728  `kimi -r`  C:\Users\user\.kimi-code\bin\kimi.exe   <- NO TCP row
          bash 7768 -> bash 10476 -> bash 5796 -> ping 8496

Discover reported C2 = explorer with 15 acts, among them
`pid 10728 kimi via pid 13236 [unlisted]` and the bash/ping chain. The
anchor found the act chain and attributed it to the nearest talking
ancestor, which was explorer, because kimi.exe owned no connection in the
Get-NetTCPConnection snapshot.

Reading (A3, A7):
1. **Liveness applies to connections, not only to children.** An agent's
   HTTP connection lives for the request; between requests the snapshot
   sees nothing, and the act chain is attributed upward to whatever
   ancestor happens to talk (here the desktop shell, through some
   extension or service). The holes text names liveness for children
   only. This is the first measured false negative of the anchor, and it
   is the common case for a CLI agent waiting on a long tool.
2. The tool did show the human what mattered: kimi.exe is in the act
   list with its path, and the bash command line it spawned is the
   agent's own audit line (`echo "| $TS | user-req | ping ..."`), so a
   reader finds the agent in one glance. The machine did not.
3. Open until win-tcp.csv and win-dns.csv are read: whether Kimi's
   connection was closed (keep-alive idle), in TIME_WAIT with owner 0, or
   over UDP/QUIC (hole: TCP only).
4. The host clock: process creation times read "10/16/2026" for boot and
   "11/2/2026 10:29 AM" for today's processes, while the local time was
   22:29 (and `git clone` failed earlier on an expired-certificate error
   consistent with a wrong clock). Timestamps from this host are not
   trustworthy as a window; recorded.
5. Explorer talking to 82.178.158.113:443 with no catalog match is itself
   a line a watcher should keep: unexplained desktop-shell traffic.

Candidates for the next HANDOFF (M5.0b or M5.4), in order:
- **Window on Windows:** the README export becomes a loop (N samples,
  T seconds apart) so a short-lived connection is caught at least once;
  discover already merges samples. Cheapest fix, no new source.
- **Recent-talk evidence:** Sysmon 3 (when present) or the TCP
  CreationTime of closed sockets is not available; without Sysmon the
  only durable trace is the DNS cache, which has names but no pid.
  Record as a hole for M5.3 to close with the os source.
- **Act-root without talk:** a process in a user directory, not a known
  shell, whose descendants are shell -> shell -> command, is reported as
  "act root, talk not seen" (a weaker class, not a candidate), so a Kimi
  between requests is at least named by the machine, not only by the
  reader. Kind: signature (image path is self-reported); evasion listed.
The commander's exports stay off the tree (process command lines of a
personal machine); this note is the record.
