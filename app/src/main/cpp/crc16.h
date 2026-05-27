#ifndef CELLLINK_CRC16_H
#define CELLLINK_CRC16_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Compute CRC-16/ARC (used by Qualcomm DIAG protocol).
 *  Polynomial: 0x8005, initial: 0x0000, reflected: true.
 */
uint16_t crc16_compute(const uint8_t* data, size_t len);

/** Verify CRC-16 on a buffer where the last two bytes are the CRC. */
bool crc16_verify(const uint8_t* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CELLLINK_CRC16_H */
