# This file should be sourced into another script.

if [ "$TARGETPLATFORM" = "linux/amd64" ]; then
	ARCH=x86_64
	CROSS_COMPILE="ccache x86_64-linux-gnu-"
elif [ "$TARGETPLATFORM" = "linux/arm64" ]; then
	ARCH=arm64 CROSS_COMPILE="ccache aarch64-linux-gnu-"
else
	echo "Unsupported target platform"; exit 1;
fi
export ARCH CROSS_COMPILE
