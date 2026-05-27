# Dragon Legion

Cross-Platform Universal Mobile Penetration Testing Platform.

"The Legion kneels to no key; it tests all doors until they are unbreakable."

## Architecture

```
dragon_legion/
├── core/               # Central platform: config, DB, HW detection, FastAPI master, Celery worker
├── modules/
│   ├── usb/            # Module 1: Sahara/Firehose, MTK BROM, Fastboot, HID brute-force
│   ├── ios/            # Module 2: checkm8, iMessage zero-click, GrayKey brute-force
│   ├── blackberry/     # Module 3: QNX RCE, BB7 loader, FIPS brute-force
│   ├── symbian/        # Module 4: XIP ROM dump, SIS traversal, Nokia NK2, P2K
│   ├── kaios/          # Module 5: Debug protocol, WASM sandbox escape
│   ├── wireless/       # Module 6: Broadpwn, Dragonblood, BlueBorne, NFC
│   ├── cellular/       # Module 6.4: Silent SMS, NAS fuzzer, rogue cell
│   ├── physical/       # Module 7: EM fault injection, CPA, chip-off, PMIC attack
│   ├── crypto/         # Module 8: FDE brute-force, kernel exploits, FS parsers
│   ├── ai/             # Module 9: RL attack scheduler, VAE protocol discovery
│   ├── supply_chain/   # Module 10: Rogue OTA server, FPGA flash MITM
│   └── post_exploitation/  # Module 8.5: Filesystem carving, data extraction
└── main.py             # CLI entry point
```

## Quick Start

```bash
# Install
sudo bash scripts/install_linux.sh

# Start master server
python -m dragon_legion.main master

# Start worker (on Linux with hardware attached)
python -m dragon_legion.main worker

# Hardware diagnostic
python -m dragon_legion.main diagnose
```

## Module Usage

### USB Attacks
```python
from dragon_legion.core.celllink_bridge import CellLinkOrchestrator

orch = CellLinkOrchestrator()
orch.connect()

# Start rogue GSM tower
tower = orch.start_tower(arfcn=10, band=0, tx_power=33)

# Bypass SIM authentication
orch.bypass_sim_auth()

# Scan RF spectrum
scanner = orch.scan_rf_spectrum()
best_ch = scanner.find_best_channel()
```

### iOS checkm8
```python
from dragon_legion.modules.ios import Checkm8Exploit, enumerate_dfu_device
import usb

dev = usb.core.find(idVendor=0x05AC, idProduct=0x1227)
with Checkm8Exploit(dev) as exploit:
    if exploit.exploit():
        print(f"GID key: {exploit.gid_key.hex()}")
```

### FDE Brute-Force (GPU)
```python
from dragon_legion.modules.crypto import parse_fde_footer, fde_derive_key

with open("userdata_dump.bin", "rb") as f:
    footer = parse_fde_footer(f.read())

if footer:
    mkek = fde_derive_key("password_candidate", footer["salt"],
                          footer["scrypt_n"], footer["scrypt_r"], footer["scrypt_p"])
```

## Hardware Requirements

| Module | Required Hardware |
|--------|------------------|
| USB attacks | Rooted Android phone with DIAG port enabled |
| iOS checkm8 | A5-A11 iOS device in DFU mode |
| Wi-Fi attacks | Monitor-mode capable adapter (RTL8812AU, AR9271) |
| NFC attacks | PN532 breakout board |
| Physical EMFI | ChipSHOUTER + XY table |
| Power analysis | 0.1Ω shunt resistor + sound card |
| LTE rogue cell | LimeSDR or USRP B200 + srsRAN |

## Documentation

- English: `docs/README.md`
- Arabic: `docs/README_AR.md`
- Per-module docs: `docs/modules/`

## License

This software is provided for authorized security testing, forensic recovery,
and educational research purposes only.
