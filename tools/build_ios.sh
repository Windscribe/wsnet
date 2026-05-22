#!/usr/bin/env bash
VERSION="1.0.0"
export PATH=/opt/homebrew/bin:$PATH

ARCHITECTURES=("SIMULATORARM64" "OS64" "TVOS" "SIMULATORARM64_TVOS")
TRIPLETS=("ws-arm64-ios-simulator" "ws-arm64-ios" "ws-arm64-tvos" "ws-arm64-tvos-simulator")

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
NumberOfCores=$(sysctl -n hw.ncpu)

updateInfoPlist() {
  plistFile=$1
  /usr/libexec/PlistBuddy -c "add :CFBundleShortVersionString string $VERSION" "$plistFile"
  /usr/libexec/PlistBuddy -c "add :CFBundleVersion string $VERSION" "$plistFile"
}

# Clean up previous builds
rm -rf temp
rm -rf bin/ios

# Build for each architecture
# shellcheck disable=SC2068
for i in ${!ARCHITECTURES[@]}; do
  arch=${ARCHITECTURES[$i]}
  triplet=${TRIPLETS[$i]}
  deploymentTarget=12
  if [ "$arch" == "TVOS" ] || [ "$arch" == "SIMULATORARM64_TVOS" ]; then
      deploymentTarget=17
  fi

  rm -rf "../generated"
  mkdir -p "temp/build/$arch"

  cmake -B "temp/build/$arch" -S .. \
    -G Xcode \
    -DCMAKE_TOOLCHAIN_FILE=$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake \
    -DVCPKG_CHAINLOAD_TOOLCHAIN_FILE=$SCRIPT_DIR/../cmake/ios.toolchain.cmake \
    -DVCPKG_TARGET_TRIPLET=$triplet \
    -DPLATFORM=$arch \
    -DDEPLOYMENT_TARGET=$deploymentTarget \
    -DSCAPIX_BRIDGE=objc \
    -DCMAKE_BUILD_TYPE=Release
  cmake --build "temp/build/$arch" -j $NumberOfCores --config Release -- \
    GCC_GENERATE_DEBUGGING_SYMBOLS=YES \
    DEBUG_INFORMATION_FORMAT=dwarf-with-dsym
  cmake --install "temp/build/$arch" --prefix "bin/ios/$arch"
   # Add missing keys to Info.plist.
     updateInfoPlist "bin/ios/$arch/wsnet.framework/Info.plist"

  # Collect dSYM for crash symbolication
  dsym=$(find "temp/build/$arch" -name "wsnet.framework.dSYM" -type d | head -1)
  if [ -n "$dsym" ]; then
    mkdir -p "bin/ios/$arch/dSYMs"
    cp -R "$dsym" "bin/ios/$arch/dSYMs/"
  else
    echo "WARNING: No dSYM found for $arch — crash symbolication will not work for this slice"
  fi
done

# Build xcframework with embedded dSYMs
XCFRAMEWORK_ARGS=()
for arch in "${ARCHITECTURES[@]}"; do
  XCFRAMEWORK_ARGS+=(-framework "./bin/ios/$arch/wsnet.framework")
  dsym_path="./bin/ios/$arch/dSYMs/wsnet.framework.dSYM"
  if [ -d "$dsym_path" ]; then
    XCFRAMEWORK_ARGS+=(-debug-symbols "$(pwd)/bin/ios/$arch/dSYMs/wsnet.framework.dSYM")
  fi
done

xcodebuild -create-xcframework \
  "${XCFRAMEWORK_ARGS[@]}" \
  -output ./build/WSNet.xcframework

rm -rf ./bin
rm -rf temp