#!/bin/sh
#
# Generate version information based on Git tags/commits.
#
# Public Domain
#
# URL: https://gist.github.com/liweitianux/9fce0fc404c41b8f28512e87fbca1562
#

dirty_mark='+'

usage() {
	cat >/dev/stderr <<EOF
usage: ${0##*/} <full|tag|count|commit> [--dirty] [default]

    full   : generate full version with tag, count and commit info
    tag    : get the last tag
    count  : get the commit count since last tag
    commit : get the current commit

    --dirty : append a mark (${dirty_mark}) if repo is dirty

    default : default tag value if no tag exists

EOF
	exit 1
}

get_last_tag() {
	git describe --tags --abbrev=0 2>/dev/null
}

get_count() {
	local tag=$(get_last_tag)
	if [ -n "${tag}" ]; then
		git rev-list ${tag}..HEAD --count
	else
		git rev-list HEAD --count
	fi
}

get_commit() {
	git rev-list --max-count=1 --abbrev-commit HEAD
}

get_full() {
	local tag=$(get_last_tag)
	if [ -n "${tag}" ]; then
		git describe --tags --always
	else
		echo "$(get_count)-$(get_commit)"
	fi
}

# Credit: https://github.com/sindresorhus/pure/issues/115
is_dirty() {
	! git diff --no-ext-diff --quiet
}

case $1 in
'' | help | -h | --help)
	usage
	;;
esac

action="$1"
shift
if [ "$1" = "--dirty" ]; then
	shift
	is_dirty && dirty=${dirty_mark} || dirty=''
fi
default="$1"

case ${action} in
full)
	echo "$(get_full)${dirty}"
	;;
tag)
	tag=$(get_last_tag)
	[ -n "${tag}" ] || tag=${default}
	echo "${tag}${dirty}"
	;;
count)
	echo "$(get_count)${dirty}"
	;;
commit)
	echo "$(get_commit)${dirty}"
	;;
*)
	usage
	;;
esac
