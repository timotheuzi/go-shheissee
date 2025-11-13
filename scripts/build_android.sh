#!/bin/bash

# Go-Shheissee Security Monitor Cross-Compilation for Android

echo "Building Go-Shheissee for Android..."

# Initialize gomobile if not already done
gomobile init 2>/dev/null

# Build Android APK using gomobile
gomobile build -target=android -o shheissee.apk ./cmd/shheissee

if [ $? -eq 0 ]; then
  echo "APK built successfully: shheissee.apk"
else
  echo "APK build failed"
  exit 1
fi

echo "To install on Android device:"
echo "adb install -r shheissee.apk"
echo "Note: Root access may be required for full monitoring features"
