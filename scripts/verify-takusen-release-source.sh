#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
actual=$(git -C "$root" remote get-url origin)
case "$actual" in
  git@github.com:takusen-io/canopy.git|https://github.com/takusen-io/canopy.git|https://github.com/takusen-io/canopy) ;;
  *)
    echo "Takusen Native Chain release requires canonical origin takusen-io/canopy; got $actual" >&2
    exit 1
    ;;
esac

if [[ -n $(git -C "$root" status --porcelain --untracked-files=all) ]]; then
  echo "Takusen Native Chain release source is dirty" >&2
  git -C "$root" status --short >&2
  exit 1
fi

git -C "$root" fetch --quiet origin takusen-integration
if ! git -C "$root" merge-base --is-ancestor HEAD origin/takusen-integration; then
  echo "release commit $(git -C "$root" rev-parse HEAD) is not published on origin/takusen-integration" >&2
  exit 1
fi

printf 'canopy_commit=%s\n' "$(git -C "$root" rev-parse HEAD)"
printf 'canopy_tree=%s\n' "$(git -C "$root" rev-parse HEAD^{tree})"
