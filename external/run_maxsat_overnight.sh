#!/usr/bin/env bash
# K4 MaxSAT overnight launcher with 8-hour wall time cap.
#
# Steps performed:
#   1. (If missing) Generate WCNF DIMACS file via dump_wcnf.py.
#   2. Run EvalMaxSAT with `gtimeout 8h` (or fallback to a wrapper that kills at 8h).
#   3. Tee solver output to a log file as it runs.
#   4. After the solver exits (optimal or timeout), invoke decode_maxsat.py
#      on the log to extract alphabets and score.
#
# Usage:
#   bash /Users/mruckman1/Desktop/dev/k4_cipher/external/run_maxsat_overnight.sh
#
# Outputs:
#   /tmp/k4_maxsat.wcnf                       (DIMACS encoding)
#   /tmp/k4_maxsat_overnight_log.txt          (solver stdout/stderr)
#   /tmp/k4_maxsat_overnight_result.json      (decoded result)

set -euo pipefail

EXTERNAL_DIR="/Users/mruckman1/Desktop/dev/k4_cipher/external"
SHINKA_DIR="/Users/mruckman1/Desktop/dev/k4_cipher/shinka"
SOLVER="${EXTERNAL_DIR}/EvalMaxSAT/build/main/EvalMaxSAT_bin"
WCNF="/tmp/k4_maxsat.wcnf"
LOG="/tmp/k4_maxsat_overnight_log.txt"

WALL_LIMIT_SECONDS=28800   # 8 hours
WALL_LIMIT_HUMAN="8h"

echo "K4 MaxSAT overnight launcher"
echo "  solver: ${SOLVER}"
echo "  wcnf:   ${WCNF}"
echo "  log:    ${LOG}"
echo "  wall:   ${WALL_LIMIT_HUMAN} hard limit"
echo

# Step 1: Ensure WCNF exists (generate if needed).
if [[ ! -f "${WCNF}" ]]; then
    echo "Generating WCNF (one-time)..."
    cd "${SHINKA_DIR}"
    . .venv/bin/activate
    python "${EXTERNAL_DIR}/dump_wcnf.py"
    deactivate || true
    echo
fi

if [[ ! -f "${WCNF}" ]]; then
    echo "ERROR: WCNF generation failed. Aborting."
    exit 1
fi

WCNF_SIZE=$(du -h "${WCNF}" | cut -f1)
echo "WCNF ready: ${WCNF} (${WCNF_SIZE})"

# Step 2: Sanity-check solver binary.
if [[ ! -x "${SOLVER}" ]]; then
    echo "ERROR: solver binary not found or not executable: ${SOLVER}"
    exit 2
fi

# Step 3: Run with hard wall-time limit.
# Prefer GNU timeout (gtimeout via coreutils), fall back to a manual wrapper.
TIMEOUT_BIN=""
if command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="gtimeout"
elif command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="timeout"
fi

START_TIME=$(date +%s)
echo
echo "Starting solver at $(date)"
echo "Output will stream to ${LOG}"
echo

if [[ -n "${TIMEOUT_BIN}" ]]; then
    # GNU timeout supports SIGTERM with optional SIGKILL after grace period.
    # --kill-after=60s sends SIGKILL 60s after the initial SIGTERM if process
    # doesn't exit gracefully. EvalMaxSAT handles SIGTERM by emitting its
    # best-so-far model before exiting.
    "${TIMEOUT_BIN}" --signal=TERM --kill-after=60s "${WALL_LIMIT_HUMAN}" \
        "${SOLVER}" "${WCNF}" 2>&1 | tee "${LOG}"
    SOLVER_EXIT=${PIPESTATUS[0]}
else
    # Manual fallback: run in background, sleep, kill.
    echo "WARNING: no timeout command found; using manual kill after ${WALL_LIMIT_SECONDS}s"
    "${SOLVER}" "${WCNF}" 2>&1 | tee "${LOG}" &
    SOLVER_PID=$!
    (sleep ${WALL_LIMIT_SECONDS} && kill -TERM ${SOLVER_PID} 2>/dev/null && \
     sleep 60 && kill -KILL ${SOLVER_PID} 2>/dev/null) &
    WATCHDOG_PID=$!
    wait ${SOLVER_PID} 2>/dev/null || true
    SOLVER_EXIT=$?
    kill ${WATCHDOG_PID} 2>/dev/null || true
fi

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
ELAPSED_H=$((ELAPSED / 3600))
ELAPSED_M=$(((ELAPSED % 3600) / 60))
echo
echo "Solver finished at $(date)"
echo "  elapsed: ${ELAPSED}s (${ELAPSED_H}h ${ELAPSED_M}m)"
echo "  exit code: ${SOLVER_EXIT}"
if [[ ${SOLVER_EXIT} -eq 124 ]]; then
    echo "  → solver hit the 8h wall limit (timeout exit code)"
    echo "  → output log should still contain any 'v' lines emitted before SIGTERM"
fi

# Step 4: Decode and score.
echo
echo "Decoding model from ${LOG}..."
cd "${SHINKA_DIR}"
. .venv/bin/activate
python "${EXTERNAL_DIR}/decode_maxsat.py" "${LOG}"
DECODE_EXIT=$?
deactivate || true

echo
echo "All done."
echo "Logs: ${LOG}"
echo "Result JSON: /tmp/k4_maxsat_overnight_result.json"
exit ${DECODE_EXIT}
