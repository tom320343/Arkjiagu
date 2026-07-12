#!/bin/bash
export ANDROID_HOME=/opt/android-sdk
export ANDROID_SDK_ROOT=/opt/android-sdk
exec /opt/gradle/bin/gradle "$@"
