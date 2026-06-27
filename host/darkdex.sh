#!/usr/bin/env bash
set -u
ARG="${1:-}"; SER="${2:-localhost:5555}"
[ -z "$ARG" ] && { echo "usage: darkdex.sh <package | app.apk> [adb-serial]"; exit 1; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HERE/native"; HOST="$HERE/host"; OUT="$HERE/dumps"; mkdir -p "$OUT"
ADB="adb -s $SER"
find_pid() { for p in $(ls /proc | grep -E '^[0-9]+$'); do
    r=$(awk '/VmRSS/{print $2}' /proc/$p/status 2>/dev/null)
    grep -qa "$1" /proc/$p/cmdline 2>/dev/null && [ "${r:-0}" -gt 100000 ] 2>/dev/null && echo "$r $p"
  done | sort -rn | head -1 | awk '{print $2}'; }
if [ "${ARG##*.}" = "apk" ] && [ -f "$ARG" ]; then
  PKG=$(python3 "$HOST/axml_pkg.py" "$ARG" 2>/dev/null)
  [ -z "$PKG" ] && { echo "could not read package name from $ARG"; exit 1; }
  echo "$ARG -> $PKG"; $ADB install -r -g "$ARG" 2>&1 | tail -1
else PKG="$ARG"; fi
echo "launching $PKG"
$ADB shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1
sleep 18
PID=$(find_pid "$PKG")
if [ -z "$PID" ]; then
  ACT=$($ADB shell cmd package resolve-activity --brief "$PKG" 2>/dev/null | tail -1 | tr -d '\r')
  [ -n "$ACT" ] && { $ADB shell am start -n "$ACT" >/dev/null 2>&1; sleep 20; PID=$(find_pid "$PKG"); }
fi
[ -z "$PID" ] && { echo "target not running"; exit 1; }
echo "host pid $PID"
DST="$OUT/$PKG"; mkdir -p "$DST"
"$BIN/darkdex_carve" "$PID" "$DST" 2>&1 | tail -1
"$BIN/darkdex_recover" "$PID" "$DST" 2>&1 | tail -1
"$BIN/darkdex_intel" "$PID" "$DST/intel.txt" 2>&1 | tail -1
echo "done -> $DST ($(ls "$DST"/*.dex 2>/dev/null | wc -l) dex)"
