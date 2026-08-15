#!/usr/bin/env bash
# darkdex v2 — full APK build (x86_64 host). Produces jniLibs for all 4 ABIs
# (libdd.so v2 engine + libdarkdex.so JNI) then gradle-builds + signs the APK.
# Needs: JDK 11, Android SDK (platform-30, build-tools;30.0.3, ndk;25.2.9519653), gradle 6.7.1
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
: "${ANDROID_SDK_ROOT:?set ANDROID_SDK_ROOT}"; : "${JAVA_HOME:?set JAVA_HOME}"
NDK="$ANDROID_SDK_ROOT/ndk/25.2.9519653"; TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
JNILIBS="$ROOT/app/app/src/main/jniLibs"; rm -rf "$JNILIBS"
declare -A CC=( [arm64-v8a]=aarch64-linux-android21 [armeabi-v7a]=armv7a-linux-androideabi21 \
                [x86]=i686-linux-android21 [x86_64]=x86_64-linux-android21 )
for abi in "${!CC[@]}"; do
  mkdir -p "$JNILIBS/$abi"; CL="$TC/${CC[$abi]}-clang++"
  "$CL" -O2 -std=c++17 -fPIE -pie -static-libstdc++ "$ROOT/native/darkdex_dump.cpp" "$ROOT/native/cdex_to_dex.cpp" -o "$JNILIBS/$abi/libdd.so"
  "$CL" -O2 -std=c++17 -shared -fPIC -static-libstdc++ "$ROOT/native/art_cookie.cpp" "$ROOT/native/cdex_to_dex.cpp" -llog -o "$JNILIBS/$abi/libdarkdex.so"
done
cd "$ROOT/app"; echo "sdk.dir=$ANDROID_SDK_ROOT" > local.properties
gradle assembleRelease --no-daemon --console=plain
BT="$ANDROID_SDK_ROOT/build-tools/30.0.3"; U=app/build/outputs/apk/release/app-release-unsigned.apk
[ -f "$ROOT/dd.keystore" ] || keytool -genkeypair -keystore "$ROOT/dd.keystore" -storepass darkdex -keypass darkdex -alias dd -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=DarkDex"
"$BT/zipalign" -f -p 4 "$U" /tmp/dd-aligned.apk
"$BT/apksigner" sign --ks "$ROOT/dd.keystore" --ks-pass pass:darkdex --key-pass pass:darkdex --out "$ROOT/darkdex.apk" /tmp/dd-aligned.apk
"$BT/apksigner" verify --verbose "$ROOT/darkdex.apk" | grep -i verified
echo "built -> $ROOT/darkdex.apk"
