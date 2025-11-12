#!/usr/bin/env bash
# Initialize a git repository for the notes and optionally create a GitHub repo using `gh`.
# Usage: bash scripts/init-git.sh
set -euo pipefail

repo_dir="$(pwd)"
repo_name="$(basename "$repo_dir")"

echo "Repository directory: $repo_dir"

if ! command -v git >/dev/null 2>&1; then
  echo "git not found. Please install git and try again." >&2
  exit 1
fi

if [ -d .git ]; then
  echo "A git repository already exists in this directory. Skipping 'git init'."
else
  echo "Initializing git repository with main branch..."
  git init -b main
fi

# Add files and commit
git add .
if git diff --cached --quiet; then
  echo "No staged changes to commit."
else
  git commit -m "chore: initial commit — OSCP notes"
fi

# Offer to create GitHub repo using gh
if command -v gh >/dev/null 2>&1; then
  read -r -p "Create GitHub repository and push? (y/N): " create_remote
  if [[ "$create_remote" =~ ^[Yy]$ ]]; then
    read -r -p "Repo name (default: $repo_name): " input_name
    repo_name="${input_name:-$repo_name}"
    read -r -p "Private repo? (y/N): " is_private
    if [[ "$is_private" =~ ^[Yy]$ ]]; then
      visibility="--private"
    else
      visibility="--public"
    fi
    echo "Creating GitHub repo '$repo_name' ($visibility) and pushing..."
    gh repo create "$repo_name" $visibility --source=. --remote=origin --push
    echo "Remote created and pushed."
  else
    echo "Skipping GitHub repo creation. To push manually, create a remote and run:"
    echo "  git remote add origin <your-remote-url> && git push -u origin main"
  fi
else
  echo "gh (GitHub CLI) not found. If you want to create a GitHub repo from the command line, install https://cli.github.com/"
  echo "To push manually, create a remote and run:"
  echo "  git remote add origin <your-remote-url> && git push -u origin main"
fi

echo "Done."
