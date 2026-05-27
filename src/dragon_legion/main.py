#!/usr/bin/env python3
"""Dragon Legion — Cross-Platform Universal Mobile Penetration Testing Platform.

"The Legion kneels to no key; it tests all doors until they are unbreakable."

Usage:
  dragon-legion master       Start the central master server
  dragon-legion worker        Start a worker node (handles hardware modules)
  dragon-legion setup         Run first-time setup
  dragon-legion diagnose      Run hardware diagnostic
  dragon-legion fuzz <device> Start protocol fuzzing on a device
"""

import sys
import argparse


def cmd_master(args):
    """Start the FastAPI central master server."""
    from dragon_legion.core.master import main
    main()


def cmd_worker(args):
    """Start a Celery worker node."""
    from dragon_legion.core.worker import celery_app
    queues = args.queues.split(",") if args.queues else ["default"]
    argv = [
        "worker",
        "--loglevel=info",
        "--queues", ",".join(queues),
        "--concurrency", str(args.concurrency),
    ]
    celery_app.worker_main(argv)


def cmd_setup(args):
    """Run first-time setup — installs dependencies, configures hardware."""
    import subprocess
    import platform

    system = platform.system()
    print("[*] Dragon Legion Setup")
    print(f"[*] Platform: {system} {platform.release()}")

    if system == "Linux":
        print("[*] Installing system packages...")
        # Check for root
        if os.geteuid() != 0:
            print("[!] Setup requires root. sudo required.")
            sys.exit(1)
        subprocess.run(["apt-get", "update"], check=False)
        subprocess.run([
            "apt-get", "install", "-y",
            "python3", "python3-pip", "python3-dev",
            "libusb-1.0-0-dev", "libssl-dev",
            "postgresql", "redis-server",
            "dnsmasq", "usbutils",
        ], check=False)
        subprocess.run(["pip", "install", "-r", "requirements.txt"], check=False)

        # udev rules
        rules = """
# Dragon Legion — USB device access
SUBSYSTEM=="usb", ATTR{idVendor}=="05c6", ATTR{idProduct}=="9008", MODE="0666"  # Qualcomm EDL
SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", ATTR{idProduct}=="0003", MODE="0666"  # MTK BROM
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", ATTR{idProduct}=="d00d", MODE="0666"  # Fastboot
SUBSYSTEM=="tty", ATTRS{idVendor}=="16c0", MODE="0666"  # Teensy
KERNEL=="hidg*", MODE="0666"  # HID gadget
"""
        with open("/etc/udev/rules.d/99-dragon-legion.rules", "w") as f:
            f.write(rules)
        subprocess.run(["udevadm", "control", "--reload-rules"], check=False)
        subprocess.run(["udevadm", "trigger"], check=False)
        print("[+] Setup complete.")

    elif system == "Windows":
        print("[*] Running Windows setup...")
        subprocess.run(["pip", "install", "-r", "requirements.txt"], check=False)
        print("[+] Setup complete. Run as master node only (hardware modules require Linux workers).")


def cmd_diagnose(args):
    """Run hardware diagnostic."""
    from dragon_legion.core.hardware import get_hardware

    print("[*] Dragon Legion Hardware Diagnostic")
    print("=" * 60)

    hw = get_hardware()
    devices = hw.detect_all()

    if not devices:
        print("[!] No attack hardware detected.")
        print("    Connect USB devices and re-run.")
        return

    print(f"\n[+] Found {len(devices)} device(s):")
    for dev in devices:
        print(f"  [{dev.hw_type.value}] {dev.name}")
        if dev.path:
            print(f"       Path: {dev.path}")
        if dev.usb_vid:
            print(f"       USB:  {dev.usb_vid}:{dev.usb_pid}")

    print(f"\n[+] Enabled modules: {', '.join(hw.enabled_modules)}")


def cmd_fuzz(args):
    """Start protocol fuzzing on a device."""
    print(f"[*] Fuzzing device: {args.device}")
    print("[*] Starting OEM command fuzzer...")
    # In production: detect device, run OEM fuzzer


def main():
    parser = argparse.ArgumentParser(
        description="Dragon Legion — Cross-Platform Universal Mobile Penetration Testing Platform",
        epilog="The Legion kneels to no key.",
    )
    sub = parser.add_subparsers(dest="command")

    # master
    p_master = sub.add_parser("master", help="Start central master server")
    p_master.set_defaults(func=cmd_master)

    # worker
    p_worker = sub.add_parser("worker", help="Start worker node")
    p_worker.add_argument("--queues", help="Comma-separated queue names")
    p_worker.add_argument("--concurrency", type=int, default=4)
    p_worker.set_defaults(func=cmd_worker)

    # setup
    p_setup = sub.add_parser("setup", help="First-time setup")
    p_setup.set_defaults(func=cmd_setup)

    # diagnose
    p_diag = sub.add_parser("diagnose", help="Hardware diagnostic")
    p_diag.set_defaults(func=cmd_diagnose)

    # fuzz
    p_fuzz = sub.add_parser("fuzz", help="Fuzz a device")
    p_fuzz.add_argument("device", help="Device identifier or serial")
    p_fuzz.set_defaults(func=cmd_fuzz)

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    import os
    main()
