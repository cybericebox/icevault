#!/bin/sh
# The required-values check of the example: every key of the tree that still holds a placeholder (CHANGE-ME or <...>).
tree="$1"
echo "Values still to set (target $2):"
cd "$tree" || exit 1
grep -rlE '=(CHANGE-ME|.*<[A-Z_]+>)' . 2>/dev/null | sort | while read -r f; do
  grep -E '=(CHANGE-ME|.*<[A-Z_]+>)' "$f" | cut -d= -f1 | while read -r k; do echo "  ${f#./} $k"; done
done
