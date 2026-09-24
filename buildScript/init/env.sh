if [[ "$HTTPS_PROXY" =~ "127.0.0.1" || "$HTTPS_PROXY" =~ "agy" ]]; then
  unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy ALL_PROXY all_proxy
fi

source buildScript/init/env_ndk.sh

if [[ "$OSTYPE" =~ ^darwin ]]; then
  export SRC_ROOT=$PWD
else
  export SRC_ROOT=$(realpath .)
fi

if [ -z "$GOPATH" ]; then
  export GOPATH=$(go env GOPATH)
fi
GOROOT=$(go env GOROOT)
if [ ! -w "$GOPATH" ]; then
  export GOPATH="$SRC_ROOT/libcore/.build/gopath"
fi

export GOMOBILE="${GOMOBILE:-$SRC_ROOT/libcore/.build/gomobile}"
export GOCACHE="${GOCACHE:-$SRC_ROOT/libcore/.build/go-cache}"
export GOMODCACHE="${GOMODCACHE:-$SRC_ROOT/libcore/.build/mod-cache}"
if [ -z "${GOBIN:-}" ] || [ ! -w "$GOBIN" ] || [ "$GOBIN" = "$GOROOT/bin" ]; then
  export GOBIN="$SRC_ROOT/libcore/.build/bin"
fi
export PATH="$GOBIN:$PATH"
mkdir -p "$GOPATH" "$GOMOBILE" "$GOCACHE" "$GOMODCACHE" "$GOBIN"

PREBUILT_HOST=$(find "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt" -mindepth 1 -maxdepth 1 -type d | head -n 1)
DEPS="$PREBUILT_HOST/bin"

export ANDROID_ARM_CC=$DEPS/armv7a-linux-androideabi21-clang
export ANDROID_ARM_CXX=$DEPS/armv7a-linux-androideabi21-clang++
export ANDROID_ARM_CC_21=$DEPS/armv7a-linux-androideabi21-clang
export ANDROID_ARM_CXX_21=$DEPS/armv7a-linux-androideabi21-clang++
export ANDROID_ARM_STRIP=$DEPS/arm-linux-androideabi-strip

export ANDROID_ARM64_CC=$DEPS/aarch64-linux-android21-clang
export ANDROID_ARM64_CXX=$DEPS/aarch64-linux-android21-clang++
export ANDROID_ARM64_STRIP=$DEPS/aarch64-linux-android-strip

export ANDROID_X86_CC=$DEPS/i686-linux-android21-clang
export ANDROID_X86_CXX=$DEPS/i686-linux-android21-clang++
export ANDROID_X86_CC_21=$DEPS/i686-linux-android21-clang
export ANDROID_X86_CXX_21=$DEPS/i686-linux-android21-clang++
export ANDROID_X86_STRIP=$DEPS/i686-linux-android-strip

export ANDROID_X86_64_CC=$DEPS/x86_64-linux-android21-clang
export ANDROID_X86_64_CXX=$DEPS/x86_64-linux-android21-clang++
export ANDROID_X86_64_STRIP=$DEPS/x86_64-linux-android-strip
