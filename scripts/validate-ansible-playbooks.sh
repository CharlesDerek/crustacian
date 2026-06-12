#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
playbook_dir=${ANSIBLE_PLAYBOOK_DIR:-ansible/playbooks}
mode=${ANSIBLE_VALIDATION_MODE:-syntax-check}
ansible_playbook=${ANSIBLE_PLAYBOOK:-}

case "$mode" in
	syntax-check)
		ansible_args="--syntax-check"
		;;
	check)
		ansible_args="--check"
		;;
	*)
		echo "Unsupported Ansible validation mode: $mode" >&2
		echo "Use ANSIBLE_VALIDATION_MODE=syntax-check or ANSIBLE_VALIDATION_MODE=check." >&2
		exit 2
		;;
esac

case "$playbook_dir" in
	/*) resolved_playbook_dir=$playbook_dir ;;
	*) resolved_playbook_dir=$repo_root/$playbook_dir ;;
esac

if [ ! -d "$resolved_playbook_dir" ]; then
	echo "No Ansible playbook directory found; skipping Ansible validation."
	exit 0
fi

if [ -z "$ansible_playbook" ]; then
	ansible_playbook=$(command -v ansible-playbook 2>/dev/null || true)
fi

if [ -z "$ansible_playbook" ] || ! command -v "$ansible_playbook" >/dev/null 2>&1; then
	echo "ansible-playbook not found; skipping Ansible playbook validation."
	exit 0
fi

playbooks_file=$(mktemp "${TMPDIR:-/tmp}/crustacian-ansible-playbooks.XXXXXX")
trap 'rm -f "$playbooks_file"' EXIT HUP INT TERM

find "$resolved_playbook_dir" -type f \( -name '*.yml' -o -name '*.yaml' \) \
	! -name 'destroy-cluster.yml' \
	! -name 'destroy-cluster.yaml' \
	! -name 'remove-longhorn-data.yml' \
	! -name 'remove-longhorn-data.yaml' \
	-print | sort >"$playbooks_file"

if [ ! -s "$playbooks_file" ]; then
	echo "No non-destructive Ansible playbooks found; skipping Ansible validation."
	exit 0
fi

status=0
while IFS= read -r playbook; do
	echo "Validating Ansible playbook with $ansible_args: $playbook"
	"$ansible_playbook" $ansible_args "$playbook" || status=1
done <"$playbooks_file"

exit "$status"
