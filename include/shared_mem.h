#ifndef SHARED_MEM_H__
#define SHARED_MEM_H__

#include "jxkr_mdapi.h"
#include <stdint.h>

#pragma pack(push, 8)

#define NORMAL_INSTRUMENT_NUM 4096
#define MAX_INSTRUMENT_NUM    NORMAL_INSTRUMENT_NUM + 1638

// 32
typedef struct sm_header {
    uint32_t magic_number;        // 0xD57A0BEE
    uint16_t reserved1;
    uint16_t instruments_number;  // 4096
    uint16_t state_len;           // length of market state  8
    uint16_t ring_buffer_len;     // length of ring buffer  8
    uint32_t content_length;
    double reserved2;             // TODO:
    double reserved3;             // TODO:
} __attribute__((__packed__)) sm_header_t;

typedef struct ring_node {
    uint32_t seq_tag_f;  // sequence, auto increase by one
    instrument_t snap;
    uint32_t seq_tag_b;
} __attribute__((__packed__)) ring_node_t;

typedef struct ring_buffer {
    ring_node_t node[MAX_INSTRUMENT_NUM];
} __attribute__((__packed__)) ring_buffer_t;

typedef struct market_state {
    uint8_t state;  // 0 not write 1 writed
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t reserved3;    // used to save expected_seq for lib
    uint64_t reserved[3];  // TODO: may not necessary
} __attribute__((__packed__)) market_state_t;

typedef struct sm_shared {
    sm_header_t header;
    market_state_t state;
    ring_buffer_t ring_buffer;
} __attribute__((__packed__)) sm_shared_t;

#pragma pack(pop)

#if defined(__cplusplus)
extern "C" {
#endif
    void* config_fpga_dma();
    void release_fpga_dma();
#if defined(__cplusplus)
}
#endif

#endif
