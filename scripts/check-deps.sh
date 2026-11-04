#!/usr/bin/env bash
# Check that the library's public packages don't (transitively) pull in
# dependencies that are only meant for tests or tooling. These packages tend to
# have import side effects and/or pull in a large body of code that bloats the
# resulting binary size unnecessarily.

# Extended regexes matched against the full import path.
forbidden=(
    '^go/.*'
    '^encoding/xml$'
    '^text/tabwriter$'
    '^testing$'
    '^github.com/cilium/ebpf/internal/testutils/testmain$'
)

set -euo pipefail

cd "$(dirname "$0")/.."

# Root and first-level packages. -e turns directories without Go files into
# entries with .Error set instead of aborting the whole listing.
mapfile -t packages < <(go list -e -f '{{if not .Error}}{{.ImportPath}}{{end}}' ./ ./*/)

# Print one "<importer> <import>" pair per line for every package in the
# transitive dependency graph of $packages, built for the given GOOS.
list_imports() {
    local goos=$1
    GOOS=$goos go list -deps \
        -f '{{range .Imports}}{{printf "%s %s\n" $.ImportPath .}}{{end}}' \
        "${packages[@]}" | sort
}

is_forbidden() {
    local import=$1
    for re in "${forbidden[@]}"; do
        if [[ "$import" =~ $re ]]; then
            return 0
        fi
    done
    return 1
}

fail=0

for goos in linux windows; do
    while read -r importer import; do
        # Only report edges into forbidden packages, not edges within it.
        if is_forbidden "$import" && ! is_forbidden "$importer"; then
            echo "GOOS=$goos: $importer imports forbidden package $import" >&2
            fail=1
        fi
    done < <(list_imports "$goos")
done

exit $fail
