#!/bin/sh
# Builds the native macOS app using the Xcode project.
set -eu
cd "$(dirname "$0")"

xcodebuild -project ClaudeUsage.xcodeproj \
    -scheme ClaudeUsage \
    -configuration Release \
    -derivedDataPath build \
    build

ditto build/Build/Products/Release/ClaudeUsage.app ClaudeUsage.app
echo "Built ClaudeUsage.app"
