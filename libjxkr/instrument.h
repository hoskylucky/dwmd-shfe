#ifndef INSTRUMENT__H__
#define INSTRUMENT__H__

#include <stdint.h>

#pragma pack(push, 8)

typedef struct instrument
{
    char instrumentId[16];
    uint32_t snapTime; // sec num
    uint16_t snapMillSec;
    float lastPrice;
    uint32_t volume;
    uint32_t openInterest;
    double turnover;

    float bidPrice[5];
    float askPrice[5];
    uint32_t bidVol[5];
    uint32_t askVol[5];

    char reserved[30];

} __attribute__((__packed__)) instrument_t;

#pragma pack(pop)

#endif
