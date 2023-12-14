#!/bin/bash
# copy-selftests.sh DEST

set -eu
set -o pipefail

series="$(echo "${KERNEL_VERSION}" | cut -d . -f 1-2)"
readonly series

readonly output="${1}"

while IFS= read -r obj; do
	if ! readelf -h "$obj" | grep -q "Linux BPF"; then
		continue
	fi

	case "$(basename "$obj")" in
	*.linked[12].o)
		# Intermediate files produced during static linking.
		continue
		;;

	linked_maps[12].o|linked_funcs[12].o|linked_vars[12].o)
		# Inputs to static linking.
		continue
		;;
	esac

	if [ "${series}" = "4.19" ]; then
		# Remove .BTF.ext, since .BTF is rewritten by pahole.
		# See https://lore.kernel.org/bpf/CACAyw9-cinpz=U+8tjV-GMWuth71jrOYLQ05Q7_c34TCeMJxMg@mail.gmail.com/
		llvm-objcopy --remove-section .BTF.ext "$obj" 1>&2
	fi

	mkdir -p "${output}/$(dirname "$obj")"
	cp -v "$obj" "${output}/$(dirname "$obj")"
done < <(find tools/testing/selftests/bpf/. -name . -o -type d -prune -o -type f -name "*.o" -print)
