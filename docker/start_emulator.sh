#!/bin/bash
# Dragon Legion — QEMU Android Emulator Startup Script
# Launches emulator with specified AVD and bridges ADB for external control.

set -e

AVD_NAME="${AVD_NAME:-pixel_7_android_14}"
ADB_PORT="${ADB_PORT:-5555}"
CONSOLE_PORT="${CONSOLE_PORT:-5554}"
EMULATOR_ARGS="${EMULATOR_ARGS:--no-window -no-audio -gpu swiftshader_indirect -memory 2048}"

echo "Starting AVD: $AVD_NAME"
echo "ADB port: $ADB_PORT"

# Start emulator in background
$ANDROID_SDK_ROOT/emulator/emulator \
    -avd "$AVD_NAME" \
    -port "$CONSOLE_PORT" \
    -read-only \
    -no-snapshot \
    -netdelay none \
    -netspeed full \
    $EMULATOR_ARGS &

EMULATOR_PID=$!

# Wait for device to boot
echo "Waiting for device to boot..."
for i in $(seq 1 60); do
    if adb -s emulator-$CONSOLE_PORT shell getprop sys.boot_completed 2>/dev/null | grep -q "1"; then
        echo "Device booted successfully"
        break
    fi
    sleep 2
done

# Enable root and debugging
adb -s emulator-$CONSOLE_PORT root 2>/dev/null || true
adb -s emulator-$CONSOLE_PORT shell setprop persist.debug.dalvik.vm 1

# Forward ADB port for external clients
adb -s emulator-$CONSOLE_PORT forward tcp:$ADB_PORT tcp:5555

echo "Emulator ready. ADB available on port $ADB_PORT"

# Keep container running
wait $EMULATOR_PID
