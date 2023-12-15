#!/bin/bash

set -euo pipefail

readonly docker="${CONTAINER_ENGINE:-docker}"

extract_oci_image() {
	local image_name=$1
	local target_directory=$2

	echo -n "Fetching $image_name... "

	# We abuse the --output flag of docker buildx to obtain a copy of the image.
	# This is simpler than creating a temporary container and using docker cp.
	# It also automatically fetches the image for us if necessary.
	if ! echo "FROM $image_name" | "$docker" buildx build --quiet --pull --output="$target_directory" - &> /dev/null; then
		echo "failed"
		return 1
	fi

	echo "ok"
	return 0
}
