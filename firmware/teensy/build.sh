#!/bin/bash
# Dragon Legion — Teensy ATmega32U4 Firmware Build Script
# Compiles hid_attack.c and produces hid_attack.hex
#
# Requirements: avr-gcc, avr-libc, avrdude
# Install: sudo apt install avr-gcc avr-libc avrdude

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE="$SCRIPT_DIR/hid_attack.c"
OUTPUT_ELF="$SCRIPT_DIR/hid_attack.elf"
OUTPUT_HEX="$SCRIPT_DIR/hid_attack.hex"
MCU="atmega32u4"
F_CPU="16000000UL"

echo "Dragon Legion — Teensy Firmware Builder"
echo "MCU: $MCU @ $F_CPU"

# Check toolchain
if ! command -v avr-gcc &>/dev/null; then
    echo "ERROR: avr-gcc not found. Run: sudo apt install avr-gcc avr-libc avrdude"
    exit 1
fi

AVR_GCC_VERSION=$(avr-gcc --version | head -1)
echo "Toolchain: $AVR_GCC_VERSION"

# Compile
echo "Compiling $SOURCE..."
avr-gcc \
    -mmcu="$MCU" \
    -DF_CPU="$F_CPU" \
    -Os \
    -Wall \
    -funsigned-char \
    -funsigned-bitfields \
    -fpack-struct \
    -fshort-enums \
    -ffunction-sections \
    -fdata-sections \
    -std=c99 \
    -o "$OUTPUT_ELF" \
    "$SOURCE"

SIZE=$(avr-size --format=avr "$OUTPUT_ELF" | tail -1)
echo "ELF built: $(wc -c < "$OUTPUT_ELF") bytes"
echo "Memory usage: $SIZE"

# Convert to Intel HEX
echo "Converting to HEX..."
avr-objcopy -O ihex -R .eeprom "$OUTPUT_ELF" "$OUTPUT_HEX"
echo "HEX built: $(wc -c < "$OUTPUT_HEX") bytes → $OUTPUT_HEX"

echo ""
echo "Build complete. To flash:"
echo "  avrdude -c usbtiny -p $MCU -U flash:w:$OUTPUT_HEX:i"
echo ""
echo "Or on Linux with bootloader:"
echo "  teensy_loader_cli -mmcu=$MCU -w -v $OUTPUT_HEX"
