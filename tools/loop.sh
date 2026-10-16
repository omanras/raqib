#!/usr/bin/env bash
# Builder -> reviews -> judge, one HANDOFF per iteration. Runs on cloud sessions
# with --cloud (spends the cloud credit) or locally without it.
# Usage: tools/loop.sh [--cloud] [--max-iter N]
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .loop docs/review

CLOUD=""; MAX=1
while [ $# -gt 0 ]; do
  case "$1" in
    --cloud) CLOUD="--cloud";;
    --max-iter) MAX="$2"; shift;;
  esac; shift
done

task_id() { sed -n 's/^# HANDOFF — \([A-Z0-9.]*\).*/\1/p' HANDOFF.md | head -1; }

for i in $(seq 1 "$MAX"); do
  T="$(task_id)"; D="$(date +%F)"
  echo "== iteration $i : $T"

  # 1) build
  claude -p "Read HANDOFF.md and do only the task it specifies." $CLOUD \
    --agent builder --permission-mode acceptEdits --permission-prompts none \
    --max-turns 60 --output-format json > ".loop/$T-build.json" || true

  # 2) reviews (paper, correctness, security) — all read-only
  claude -p "Review HEAD against HANDOFF.md and docs/CONSTITUTION.md. Write the packet to docs/review/$D-$T.md" $CLOUD \
    --agent reviewer --permission-prompts none --output-format json > ".loop/$T-review.json" || true
  claude -p "/code-review high --max-findings 20" $CLOUD \
    --permission-prompts none --output-format json > ".loop/$T-cr.json" || true

  # commit the packet so the tree stays ground truth
  git add docs/review && git commit -qm "Review packet $T" || true

  # 3) judge — three options only
  verdict="$(claude -p "Read HANDOFF.md, docs/DEVELOPMENT_PLAN.md and the newest file in docs/review/. Also read .loop/$T-cr.json result. Decide." $CLOUD \
    --agent judge --permission-prompts none --output-format json \
    --json-schema '{"type":"object","properties":{"decision":{"enum":["NEXT","REDO","STOP"]},"reason":{"type":"string"},"fix_order":{"type":"string"}},"required":["decision","reason"]}' \
    | tee ".loop/$T-judge.json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["structured_output"]["decision"])')"

  # cost of this iteration (client-side estimate)
  python3 - <<'PY' "$T"
import json,sys,glob
t=sys.argv[1]; tot=0.0
for f in glob.glob(f".loop/{t}-*.json"):
    try: tot+=float(json.load(open(f)).get("total_cost_usd",0))
    except Exception: pass
print(f"[loop] {t} cost ~ ${tot:.2f}")
PY

  case "$verdict" in
    NEXT) tools/next-task.sh ;;
    REDO) order="$(python3 -c 'import json;print(json.load(open(".loop/'"$T"'-judge.json"))["structured_output"].get("fix_order",""))')"
          printf '\nREDO: %s\n' "$order" >> HANDOFF.md ;;
    *)    echo "[loop] STOP at $T — see docs/review/"; exit 2 ;;
  esac
done
