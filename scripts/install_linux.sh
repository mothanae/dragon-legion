#!/bin/bash
# Dragon Legion — Linux Setup Script
# Installs all system packages, Python dependencies, compiles C/CUDA code,
# sets up udev rules, configures USB gadget kernel modules,
# and flashes Teensy firmware.
#
# Run as: sudo bash install_linux.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ⚔  Dragon Legion — Linux Setup"
echo "  The Legion kneels to no key."
echo -e "${NC}"

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Setup requires root. Run with sudo.${NC}"
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
echo -e "${GREEN}[*] Installing system packages...${NC}"
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-dev python3-venv \
    libusb-1.0-0-dev libssl-dev libffi-dev \
    postgresql postgresql-client redis-server \
    dnsmasq usbutils pciutils \
    build-essential cmake gcc g++ \
    avrdude dfu-programmer \
    libgmp-dev libmpfr-dev libmpc-dev \
    i2c-tools spi-tools \
    git curl wget unzip

# ---------------------------------------------------------------------------
# 2. Python dependencies
# ---------------------------------------------------------------------------
echo -e "${GREEN}[*] Installing Python packages...${NC}"
cd "$(dirname "$0")/.."
pip install --upgrade pip
pip install -r requirements.txt

# ---------------------------------------------------------------------------
# 3. Compile C extensions
# ---------------------------------------------------------------------------
echo -e "${GREEN}[*] Compiling C performance modules...${NC}"
if [ -d "src/c" ] && [ "$(ls -A src/c/*.c 2>/dev/null)" ]; then
    for cfile in src/c/*.c; do
        name=$(basename "$cfile" .c)
        gcc -O3 -march=native -fPIC -shared \
            -o "src/c/${name}.so" "$cfile" \
            $(python3-config --includes --ldflags)
        echo "  Compiled: ${name}.so"
    done
fi

# ---------------------------------------------------------------------------
# 4. CUDA kernels (if nvcc available)
# ---------------------------------------------------------------------------
if command -v nvcc &> /dev/null && [ -d "src/cuda" ] && [ "$(ls -A src/cuda/*.cu 2>/dev/null)" ]; then
    echo -e "${GREEN}[*] Compiling CUDA kernels...${NC}"
    for cufile in src/cuda/*.cu; do
        name=$(basename "$cufile" .cu)
        nvcc -O3 -arch=sm_75 -shared -Xcompiler -fPIC \
            -o "src/cuda/${name}.so" "$cufile"
        echo "  Compiled: ${name}.so"
    done
else
    echo "  No CUDA compiler found — skipping GPU kernels"
fi

# ---------------------------------------------------------------------------
# 5. udev rules
# ---------------------------------------------------------------------------
echo -e "${GREEN}[*] Installing udev rules...${NC}"
cat > /etc/udev/rules.d/99-dragon-legion.rules << 'UDEVEOF'
# Dragon Legion — USB device access for mobile penetration testing
SUBSYSTEM=="usb", ATTR{idVendor}=="05c6", ATTR{idProduct}=="9008", MODE="0666", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", ATTR{idProduct}=="0003", MODE="0666", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="d00d", MODE="0666", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="4ee0", MODE="0666", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", ATTR{idProduct}=="685d", MODE="0666", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="05ac", ATTR{idProduct}=="1227", MODE="0666", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="16c0", MODE="0666", TAG+="uaccess"
SUBSYSTEM=="usb", ATTR{idVendor}=="04d8", ATTR{idProduct}=="fc92", MODE="0666", TAG+="uaccess"
SUBSYSTEM=="tty", ATTRS{idVendor}=="16c0", MODE="0666", TAG+="uaccess"
SUBSYSTEM=="tty", ATTRS{idVendor}=="0403", MODE="0666", TAG+="uaccess"
KERNEL=="hidg*", MODE="0666"
UDEVEOF

udevadm control --reload-rules
udevadm trigger
echo "  udev rules installed and reloaded"

# ---------------------------------------------------------------------------
# 6. USB gadget kernel modules
# ---------------------------------------------------------------------------
echo -e "${GREEN}[*] Configuring USB gadget kernel modules...${NC}"
modprobe libcomposite 2>/dev/null || echo "  libcomposite already loaded or unavailable"
if [ ! -d /sys/kernel/config/usb_gadget ]; then
    mount -t configfs none /sys/kernel/config 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 7. Flash Teensy firmware (if Teensy connected)
# ---------------------------------------------------------------------------
if lsusb | grep -q "16c0:0483\|16c0:0478"; then
    echo -e "${GREEN}[*] Teensy detected — flashing HID brute-force firmware...${NC}"
    if [ -f "firmware/teensy/hid_attack.hex" ]; then
        avrdude -c usbtiny -p atmega32u4 -U flash:w:firmware/teensy/hid_attack.hex:i
    else
        echo "  Teensy firmware not found in firmware/teensy/"
    fi
fi

# ---------------------------------------------------------------------------
# 8. PostgreSQL setup
# ---------------------------------------------------------------------------
echo -e "${GREEN}[*] Configuring PostgreSQL...${NC}"
if systemctl is-active postgresql &>/dev/null; then
    su - postgres -c "psql -c \"CREATE USER dragon_legion WITH PASSWORD 'dragon_legion';\"" 2>/dev/null || true
    su - postgres -c "psql -c \"CREATE DATABASE dragon_legion OWNER dragon_legion;\"" 2>/dev/null || true
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE dragon_legion TO dragon_legion;\"" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 9. External tools (srsRAN for LTE attacks, hashcat for GPU cracking)
# ---------------------------------------------------------------------------
echo -e "${GREEN}[*] Checking external tools...${NC}"
if ! command -v srsenb &>/dev/null; then
    echo "  srsRAN not found — install for LTE rogue cell attacks:"
    echo "    sudo add-apt-repository ppa:srslte/releases"
    echo "    sudo apt install srsran"
else
    echo "  srsRAN: $(srsenb --version 2>&1 | head -1 || echo 'installed')"
fi
if ! command -v hashcat &>/dev/null; then
    echo "  hashcat not found — install for GPU-accelerated cracking:"
    echo "    sudo apt install hashcat"
else
    echo "  hashcat: $(hashcat --version)"
fi

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${GREEN}  Dragon Legion setup complete.${NC}"
echo ""
echo "  Start master:   dragon-legion master"
echo "  Start worker:   dragon-legion worker"
echo "  Hardware diag:  dragon-legion diagnose"
echo ""
echo -e "${CYAN}  The Legion kneels to no key; it tests all${NC}"
echo -e "${CYAN}  doors until they are unbreakable.${NC}"
echo -e "${CYAN}============================================${NC}"
