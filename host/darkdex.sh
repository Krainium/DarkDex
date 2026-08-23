#!/usr/bin/env bash
# darkdex v2 — one-shot unpacker for the redroid host.
#
# v1: launch, sleep, take ONE /proc/mem snapshot, carve + recover + intel.
# v2 adds, all from OUTSIDE the Android sandbox (invisible to iJiami anti-debug):
#   * JIT-release tracer  — bpftrace uprobes on ART's dex-open + class-define path
#                           capture every decrypted dex the instant ART opens it,
#                           BEFORE anti-scan header wiping, across anti-debug
#                           respawns, plus a live class map. (native/darkdex_trace.bt)
#   * artwalk             — recover dex from live art::DexFile objects (exact
#                           begin_/size_) even when header AND map_list are wiped.
#   * cdex->dex           — real CompactDex code-item expansion so dumps decompile.
#   * dexval              — validate, de-dup, rank, and (if baksmali present) smoke
#                           test disassembly; winners land in dumps/<pkg>/best/.
#
# usage: darkdex.sh <package | app.apk> [adb-serial] [--no-trace] [--baksmali]
set -u
# default serial: first connected device (adb distinguishes localhost:5555 from
# 127.0.0.1:5555 as separate transports, so never hardcode — auto-detect)
ARG="${1:-}"; SER="$(adb devices 2>/dev/null | awk 'NR>1 && $2=="device"{print $1; exit}')"; SER="${SER:-127.0.0.1:5555}"; TRACE=1; BAKSMALI=""
shift || true
for a in "$@"; do case "$a" in
  --no-trace) TRACE=0;; --baksmali) BAKSMALI="--baksmali";; *) SER="$a";; esac; done
[ -z "$ARG" ] && { echo "usage: darkdex.sh <package|app.apk> [serial] [--no-trace] [--baksmali]"; exit 1; }

HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HERE/native"; HOST="$HERE/host"; OUT="$HERE/dumps"; mkdir -p "$OUT"
ADB="adb -s $SER"

# --- build native cores if missing ---
for t in darkdex_carve darkdex_recover darkdex_intel darkdex_artwalk darkdex_grab; do
  [ -x "$BIN/$t" ] || g++ -O2 -std=c++17 -o "$BIN/$t" "$BIN/$t.cpp" || { echo "build $t failed"; exit 1; }
done
[ -x "$BIN/cdex_to_dex" ] || g++ -O2 -std=c++17 -DDARKDEX_STANDALONE -o "$BIN/cdex_to_dex" "$BIN/cdex_to_dex.cpp"

# --- resolve package (install apk if given) ---
if [ "${ARG##*.}" = "apk" ] && [ -f "$ARG" ]; then
  PKG=$(python3 "$HOST/axml_pkg.py" "$ARG" 2>/dev/null)
  [ -z "$PKG" ] && { echo "cannot read package from $ARG"; exit 1; }
  echo "$ARG -> $PKG"; $ADB install -r -g "$ARG" 2>&1 | tail -1
else PKG="$ARG"; fi
DST="$OUT/$PKG"; rm -rf "$DST"; mkdir -p "$DST"

# --- container pid + ART lib paths (for host-side uprobes into the guest) ---
CPID="$(docker inspect -f '{{.State.Pid}}' redroid 2>/dev/null || true)"
LIBDEX=""; LIBART=""
if [ -n "$CPID" ]; then
  for base in /apex/com.android.art/lib64 /apex/com.android.runtime/lib64 /system/lib64; do
    [ -f "/proc/$CPID/root$base/libdexfile.so" ] && LIBDEX="/proc/$CPID/root$base/libdexfile.so"
    [ -f "/proc/$CPID/root$base/libart.so" ]     && LIBART="/proc/$CPID/root$base/libart.so"
  done
fi

# --- map guest pid -> host pid via NSpid ---
host_pid() {
  local g="$1" p ns
  for p in $(ls /proc | grep -E '^[0-9]+$'); do
    ns=$(awk '/^NSpid:/{print $NF}' "/proc/$p/status" 2>/dev/null)
    [ "$ns" = "$g" ] && { echo "$p"; return; }
  done
}

# --- start the JIT tracer BEFORE launch so we catch the first decrypt ---
TRACE_PID=""
if [ "$TRACE" = 1 ] && command -v bpftrace >/dev/null 2>&1 && [ -n "$LIBDEX" ] && [ -n "$LIBART" ]; then
  BT="$DST/trace.bt"
  sed -e "s#@LIBDEX@#$LIBDEX#g" -e "s#@LIBART@#$LIBART#g" \
      -e '/@COMM@/d' -e '/^BEGIN/d' -e '/DARKDEX_TRACE_READY/d' "$BIN/darkdex_trace.bt" > "$BT"
  echo "[*] JIT tracer arming (bpftrace uprobes on ART dex-open + DefineClass)"
  ( stdbuf -oL bpftrace "$BT" 2>"$DST/trace.err" \
      | stdbuf -oL tee "$DST/events.log" \
      | "$BIN/darkdex_grab" "$DST" "$PKG" >"$DST/grab.log" 2>&1 ) &
  TRACE_PID=$!
  # always tear the tracer down, even on early exit (else it orphans + hangs ssh)
  trap 'kill "$TRACE_PID" 2>/dev/null; pkill -P "$TRACE_PID" 2>/dev/null; pkill -f "bpftrace $BT" 2>/dev/null' EXIT
  sleep 4
else
  [ "$TRACE" = 1 ] && echo "[!] tracer unavailable (need bpftrace + redroid libart); snapshot only"
fi

# --- launch (fresh, so the packer re-decrypts under the tracer) ---
ACT=$($ADB shell cmd package resolve-activity --brief -c android.intent.category.LAUNCHER "$PKG" 2>/dev/null | tail -1 | tr -d '\r')
launch(){ [ -n "$ACT" ] && $ADB shell am start -n "$ACT" >/dev/null 2>&1 && return;
          $ADB shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1; }
rss_of(){ $ADB shell cat /proc/"$1"/status 2>/dev/null | awk '/VmRSS/{print $2}' | tr -dc '0-9'; }

# If a loaded instance is already up, attach to it (hardened apps that crash-loop
# on cold start are unreliable to force-stop+relaunch). Trace mode then nudges the
# UI so lazily-decrypted classes still fire the DefineClass/OpenCommon probes.
GPID=$($ADB shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
if [ -n "$GPID" ] && [ "$(rss_of "$GPID")" -gt 150000 ] 2>/dev/null; then
  echo "[*] attaching to running $PKG (pid $GPID, loaded)"
  [ "$TRACE" = 1 ] && { echo "[*] nudging UI to trigger lazy dex/class opens";
    for k in 20 22 4 20 22 4; do $ADB shell input keyevent $k >/dev/null 2>&1; sleep 1; done; }
else
  echo "[*] launching $PKG"
  $ADB shell am force-stop "$PKG" 2>/dev/null; sleep 1; launch
  for i in $(seq 1 60); do
    GPID=$($ADB shell pidof "$PKG" 2>/dev/null | tr -d '\r' | awk '{print $1}')
    [ -n "$GPID" ] && break
    [ $((i % 15)) -eq 0 ] && launch
    sleep 1
  done
fi
[ -z "$GPID" ] && { echo "target did not start"; [ -n "$TRACE_PID" ] && kill "$TRACE_PID" 2>/dev/null; exit 1; }
HPID=$(host_pid "$GPID")
echo "[*] guest pid $GPID -> host pid ${HPID:-?}"
last=0; for i in $(seq 1 20); do
  r=$(rss_of "$GPID")
  [ "${r:-0}" -gt 150000 ] 2>/dev/null && [ "$r" = "$last" ] && break
  last=${r:-0}; sleep 2
done
echo "[*] RSS ~${last}kB; draining class map, then snapshotting"
sleep 6   # let DefineClass events flush through the tracer

# --- snapshot cores (host pid preferred; fall back to package scan) ---
TID="${HPID:-$PKG}"
echo "[*] artwalk";  "$BIN/darkdex_artwalk"  "$TID" "$DST" 2>&1 | tail -2
echo "[*] carve";    "$BIN/darkdex_carve"    "$TID" "$DST" 2>&1 | tail -2
echo "[*] recover";  "$BIN/darkdex_recover"  "$TID" "$DST" 2>&1 | tail -2
echo "[*] intel";    "$BIN/darkdex_intel"    "$TID" "$DST/intel.txt" 2>&1 | tail -1

# --- stop tracer ---
if [ -n "$TRACE_PID" ]; then
  pkill -P "$TRACE_PID" 2>/dev/null; kill "$TRACE_PID" 2>/dev/null; sleep 1
  echo "[*] tracer: $(grep -c DEXOPEN "$DST/events.log" 2>/dev/null) dex-opens, $(wc -l < "$DST/classes.trace.txt" 2>/dev/null) classes"
fi

# --- convert any CompactDex to standard dex ---
for c in "$DST"/*.cdex; do
  [ -f "$c" ] || continue
  "$BIN/cdex_to_dex" "$c" "${c%.cdex}.fromcdex.dex" 2>/dev/null && echo "[*] cdex->dex $(basename "$c")"
done

# --- validate / de-dup / rank ---
echo "[*] validating dumps"
python3 "$HOST/dexval.py" "$DST" $BAKSMALI --hint "$(echo "$PKG" | cut -d. -f2)" 2>&1 | sed 's/^/    /'
echo "[done] -> $DST   (best dex in $DST/best/, class map in classes.trace.txt, intel in intel.txt)"
