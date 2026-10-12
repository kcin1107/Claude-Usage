#!/bin/sh
# Builds the native macOS app using the Xcode project.
set -eu
cd "$(dirname "$0")"

xcodebuild -project Crescent.xcodeproj \
    -scheme Crescent \
    -configuration Release \
    -derivedDataPath build \
    SDK_STAT_CACHE_ENABLE=NO \
    build

ditto build/Build/Products/Release/Crescent.app Crescent.app
echo "Built Crescent.app"
