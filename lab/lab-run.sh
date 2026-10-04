#!/usr/bin/env bash
# Exercise incredigo end-to-end against the fake lab store. Read-mostly; the only
# writes are into the throwaway gopass store and sealed bundles in the lab dir.
set -uo pipefail
export PATH=/usr/local/bin:$PATH
export GOPASS_HOMEDIR="$HOME/.lab-gopass"
export GNUPGHOME="$HOME/.lab-gnupg"
export GOPASS_NO_NOTIFY=true
export INCREDIGO_PASSPHRASE='lab-seal-pass-correct-horse'
cd "$HOME/lab"

run() { echo; echo "############ $* ############"; "$@"; echo "---- exit=$? ----"; }

run incredigo scan
run incredigo status
run incredigo migrate --dedupe
echo; echo "## gopass store after migrate:"; gopass ls --flat
run incredigo export --prefix imported/ --out "$HOME/lab/backup.age"
run incredigo import --in "$HOME/lab/backup.age" --prefix restored/
echo; echo "## store after import:"; gopass ls --flat
run incredigo rotate --prefix imported/ --dry-run --blast --blast-root "$HOME/lab"
run incredigo worklist
echo; echo "LAB_RUN_DONE"
