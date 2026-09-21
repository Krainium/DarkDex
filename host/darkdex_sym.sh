#!/usr/bin/env bash
set -u

die(){ echo "$*" >&2; exit 1; }

CONTAINER=""; LIBDEX=""; LIBART=""
if [ "${1:-}" = "--libs" ]; then
  LIBDEX="$2"; LIBART="$3"; TMPL="$4"; OUT="$5"
else
  CONTAINER="${1:-}"; TMPL="${2:-}"; OUT="${3:-}"
  [ -z "$CONTAINER" ] && die "usage: darkdex_sym.sh <container> <template.bt> <out.bt>"
  CPID="$(docker inspect -f '{{.State.Pid}}' "$CONTAINER" 2>/dev/null)"
  [ -z "$CPID" ] && die "container $CONTAINER not running"
  for base in /apex/com.android.art/lib64 /apex/com.android.runtime/lib64 /system/lib64; do
    p="/proc/$CPID/root$base/libdexfile.so"
    [ -f "$p" ] && LIBDEX="$p"
    p="/proc/$CPID/root$base/libart.so"
    [ -f "$p" ] && LIBART="$p"
  done
fi

[ -f "$TMPL" ] || die "template not found: $TMPL"
[ -f "$LIBDEX" ] || die "libdexfile.so not found"
[ -f "$LIBART" ] || die "libart.so not found"
[ -n "$OUT" ] || die "output path required"

echo "[sym] libdexfile: $LIBDEX"
echo "[sym] libart:     $LIBART"

DEX_SYMS=$(nm -D --defined-only "$LIBDEX" 2>/dev/null | awk '{print $3}')
ART_SYMS=$(nm -D --defined-only "$LIBART"  2>/dev/null | awk '{print $3}')

kept=0; dropped=0

{
  skip_block=0
  brace_depth=0
  while IFS= read -r line; do
    filled="${line//@LIBDEX@/$LIBDEX}"
    filled="${filled//@LIBART@/$LIBART}"

    if [ "$skip_block" -eq 1 ]; then
      opens=$(echo "$filled"  | tr -cd '{' | wc -c)
      closes=$(echo "$filled" | tr -cd '}' | wc -c)
      brace_depth=$(( brace_depth + opens - closes ))
      if [ "$brace_depth" -le 0 ]; then
        skip_block=0; brace_depth=0
      fi
      continue
    fi

    if echo "$filled" | grep -qE '^uprobe:'; then
      sym="$(echo "$filled" | sed 's/uprobe:[^:]*://; s/{.*//' | tr -d ' \t')"
      if echo "$filled" | grep -q "@LIBDEX@\|$LIBDEX"; then
        found=$(echo "$DEX_SYMS" | grep -cxF "$sym" 2>/dev/null || true)
      else
        found=$(echo "$ART_SYMS" | grep -cxF "$sym" 2>/dev/null || true)
      fi
      if [ "${found:-0}" -gt 0 ]; then
        echo "$filled"
        kept=$((kept+1))
      else
        echo "/* [sym] ABSENT: $sym */"
        dropped=$((dropped+1))
        skip_block=1; brace_depth=0
      fi
    else
      echo "$filled"
    fi
  done < "$TMPL"
} > "$OUT"

echo "[sym] wrote $OUT  ($kept probes active, $dropped absent/skipped)"
