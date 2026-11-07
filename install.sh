#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILLS_DIR="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
TARGET="$SKILLS_DIR/ai-security-guard"

if [ -e "$TARGET" ]; then
  echo "目标已存在：$TARGET"
  echo "先备份或删除它，再重跑本脚本。"
  exit 1
fi

mkdir -p "$SKILLS_DIR"
cp -R "$REPO_DIR" "$TARGET"
rm -rf "$TARGET/.git" "$TARGET/__pycache__" "$TARGET/scripts/__pycache__" "$TARGET/tests/__pycache__"

echo "已安装到：$TARGET"
echo
echo "试跑："
echo "  python \"$TARGET/scripts/guard.py\" scan ."
echo
echo "在你的项目里装自动体检："
echo "  cd /path/to/your-project"
echo "  python \"$TARGET/scripts/guard.py\" install-hook"
