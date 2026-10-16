#!/usr/bin/env bash
# Raqib loop v2 — builder in a CLOUD session (spends the cloud credit), reviews
# and judge LOCAL with -p. The cloud session is launched with `claude --cloud`
# (returns immediately) and watched through GitHub: the builder must push its
# work to branch claude/<task>. REDO messages go to the same session with
# `claude -p "<msg>" --cloud <session-id>`.
#
# Usage: tools/loop.sh [--max-iter N] [--poll SEC] [--timeout SEC]
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .loop docs/review

MAX=1; POLL=60; TIMEOUT=2700
while [ $# -gt 0 ]; do
  case "$1" in
    --max-iter) MAX="$2"; shift;;
    --poll)     POLL="$2"; shift;;
    --timeout)  TIMEOUT="$2"; shift;;
    --cloud)    ;;   # accepted for compatibility; builder is always cloud here
  esac; shift
done

task_id() { sed -n 's/^# HANDOFF — \([A-Za-z0-9.]*\).*/\1/p' HANDOFF.md | head -1; }

launch_builder() {  # $1 = task, $2 = extra instruction (REDO) or empty
  local T="$1" extra="${2:-}"
  local prompt="Read HANDOFF.md and do only the task it specifies. When done, push your single commit to branch claude/$T (never main). $extra"
  # `claude --cloud` refuses to start without a TTY, so run it inside a
  # pseudo-terminal via `script`; its output (incl. the session id) is recorded.
  script -qfec "claude --cloud \"$prompt\"" ".loop/$T-launch.txt" >/dev/null 2>&1 </dev/null || true
  sed -n 's/.*\(session_[A-Za-z0-9]\{10,\}\).*/\1/p' ".loop/$T-launch.txt" | head -1
}

wait_for_branch() {  # $1 = task ; prints commit sha or empty on timeout
  local T="$1" waited=0 sha=""
  while [ "$waited" -lt "$TIMEOUT" ]; do
    sha="$(git ls-remote --heads origin "claude/$T" 2>/dev/null | awk '{print $1}')"
    if [ -n "$sha" ]; then
      git fetch -q origin "claude/$T:refs/remotes/origin/claude/$T" 2>/dev/null || true
      local msg; msg="$(git log -1 --pretty=%s "origin/claude/$T" 2>/dev/null || true)"
      case "$msg" in landed:*|STOP:*) echo "$sha"; return 0;; esac
    fi
    sleep "$POLL"; waited=$((waited+POLL))
    echo "[loop] waiting for claude/$T ... ${waited}s"
  done
  echo ""
}

judge_once() {  # prints NEXT|REDO|STOP ; fix order saved to .loop/<T>-fix.txt
  local T="$1"
  claude -p "Read HANDOFF.md, docs/DEVELOPMENT_PLAN.md, the newest file in docs/review/ and .loop/$T-cr.txt. Decide." \
    --agent judge --permission-prompts none --output-format json \
    --json-schema '{"type":"object","properties":{"decision":{"enum":["NEXT","REDO","STOP"]},"reason":{"type":"string"},"fix_order":{"type":"string"}},"required":["decision","reason"]}' \
    > ".loop/$T-judge.json" || true
  python3 - "$T" <<'PY'
import json,sys
T=sys.argv[1]
try:
    d=json.load(open(f".loop/{T}-judge.json"))["structured_output"]
except Exception:
    d={"decision":"STOP","reason":"judge output unreadable","fix_order":""}
open(f".loop/{T}-fix.txt","w").write(d.get("fix_order",""))
open(f".loop/{T}-reason.txt","w").write(d.get("reason",""))
print(d["decision"])
PY
}

for i in $(seq 1 "$MAX"); do
  T="$(task_id)"; D="$(date +%F)"
  echo "== iteration $i : $T"
  git pull -q --ff-only origin main || true

  # 1) builder in the cloud (or --watch-only: you launched it by hand)
  if [ "${WATCH_ONLY:-0}" = "1" ]; then
    SID="$(cat ".loop/$T-session.txt" 2>/dev/null || true)"
    echo "[loop] watch-only: waiting for claude/$T (session ${SID:-unknown})"
  else
    SID="$(launch_builder "$T")"
    if [ -z "$SID" ]; then
      echo "[loop] could not start a cloud session. Output was:"; cat ".loop/$T-launch.txt"
      echo "[loop] Launch it by hand in a terminal:  claude --cloud \"Read HANDOFF.md and do only the task it specifies. Push to branch claude/$T.\""
      echo "[loop] then re-run:  WATCH_ONLY=1 tools/loop.sh"; exit 4
    fi
    echo "[loop] cloud session: $SID  (claude.ai/code)"
    echo "$SID" > ".loop/$T-session.txt"
  fi

  # 2) wait for claude/<T> with a landed:/STOP: commit
  SHA="$(wait_for_branch "$T")"
  if [ -z "$SHA" ]; then echo "[loop] TIMEOUT waiting for claude/$T — STOP"; exit 2; fi
  MSG="$(git log -1 --pretty=%s "origin/claude/$T")"
  echo "[loop] builder: $MSG"
  case "$MSG" in STOP:*) echo "[loop] builder STOPped — see docs/review on the branch"; exit 2;; esac

  # 3) reviews, local and read-only, against the branch checked out in a worktree
  rm -rf ".loop/wt" && git worktree add -q ".loop/wt" "origin/claude/$T"
  ( cd ".loop/wt" && \
    claude -p "Review HEAD against HANDOFF.md and docs/CONSTITUTION.md. Write the packet to docs/review/$D-$T.md" \
      --agent reviewer --permission-prompts none --output-format json > "../$T-review.json" || true ; \
    claude -p "/code-review high --max-findings 20" --permission-prompts none --output-format json \
      | python3 -c 'import json,sys; print(json.load(sys.stdin).get("result",""))' > "../$T-cr.txt" || true )
  # reviewer may only write docs/review; copy its packet into the main tree
  cp ".loop/wt/docs/review/$D-$T.md" "docs/review/$D-$T.md" 2>/dev/null || true
  git worktree remove --force ".loop/wt" 2>/dev/null || true

  # 4) judge, local
  V="$(judge_once "$T")"
  echo "[loop] judge: $V — $(cat ".loop/$T-reason.txt")"

  # 5) cost of the local parts (cloud cost is on the credit page)
  python3 - "$T" <<'PY'
import json,sys,glob
T=sys.argv[1]; tot=0.0
for f in glob.glob(f".loop/{T}-*.json"):
    try: tot+=float(json.load(open(f)).get("total_cost_usd",0))
    except Exception: pass
print(f"[loop] {T} local cost ~ ${tot:.2f} (builder cost: see cloud credit page)")
PY

  case "$V" in
    NEXT)
      git merge -q --ff-only "origin/claude/$T"
      git add docs/review && git commit -qm "Review packet $T" || true
      tools/gate.sh
      git push -q origin main
      tools/next-task.sh && git push -q origin main ;;
    REDO)
      FIX="$(cat ".loop/$T-fix.txt")"
      echo "[loop] REDO -> messaging session $SID"
      claude -p "REDO from the judge: $FIX  Fix inside the same scope, amend or add one commit, push to claude/$T again." --cloud "$SID" || true
      git push -q origin --delete "claude/$T" 2>/dev/null || true   # wait for a fresh push
      SHA="$(wait_for_branch "$T")"; [ -z "$SHA" ] && { echo "[loop] REDO timeout"; exit 2; }
      echo "[loop] REDO landed; re-run the loop to review it"; exit 3 ;;
    *)
      git add docs/review && git commit -qm "Review packet $T (STOP)" || true
      git push -q origin main || true
      echo "[loop] STOP at $T — commander decides"; exit 2 ;;
  esac
done
