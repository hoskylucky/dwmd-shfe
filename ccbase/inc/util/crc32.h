#ifndef CRC32_H_
#define CRC32_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif
    uint32_t crc32(const void *buf, uint32_t size);
#ifdef __cplusplus
}
#endif
#endif
