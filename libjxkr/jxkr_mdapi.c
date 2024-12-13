#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE
#endif
#include <sched.h>

#include "jxkr_mdapi.h"
#include "shared_mem.h"
#include "check_mac.h"
#include "tsd_mdapi.h"

#include "iniparser.h"

#include "util/aes.h"
#include "util/base64.h"
#include "util/misc.h"
#include "util/crc32.h"

#define DATA_LENGH 256

#define API_VERSION "v2.4"

#define CHECK_AUTH() \
    if (!authroized) \
        return JXKR_MD_NOT_AUTHORIZED;

// #define CHECK_AUTH() ;

static void (*callback)(instrument_t *) = NULL;
static pthread_t apiThread = 0;
static int cpu_id = 0;
static bool authroized = false;
static int *pIsAlive;
static sm_shared_t *g_sm = NULL;

static void assignToThisCore(int core_id)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

/**
 * @brief read ring buffer and check if there is md data update
 */
volatile uint64_t current_seq = 0;
uint64_t expected_seq = 0;

bool file_saved = false;

instrument_t *jxkr_next()
{
    instrument_t *res = NULL;
    if (g_sm->ring_buffer.node[current_seq].seq_tag_b != expected_seq)
    {
        if (current_seq >= NORMAL_INSTRUMENT_NUM)
            current_seq = current_seq - NORMAL_INSTRUMENT_NUM;

        // if (g_sm->ring_buffer.node[current_seq].seq_tag_b != 0 && !file_saved)
        // {
        //     printf("saved %ld %u %ld \n", current_seq, g_sm->ring_buffer.node[current_seq].seq_tag_b, expected_seq);
        //     printf("size %lu %lu %lu %lu \n", sizeof(sm_shared_t), sizeof(sm_header_t), sizeof(ring_node_t), sizeof(instrument_t));
        //     file_saved = true;
        //     FILE *f = fopen("./mem.dat", "wb");
        //     fwrite(g_sm, sizeof(sm_shared_t), 1, f);
        //     fclose(f);
        //     printf("saved");
        // }
    }
    else
    {
        res = &g_sm->ring_buffer.node[current_seq].snap;
        expected_seq++;
        current_seq++;
        if (current_seq >= MAX_INSTRUMENT_NUM)
            current_seq = current_seq - NORMAL_INSTRUMENT_NUM;
    }
    return res;
}

jxkr_md_status_t jxkr_prepare()
{
    if (g_sm == NULL)
        return JXKR_MD_SHARED_MEMORY_ERROR;
    expected_seq = g_sm->ring_buffer.node[current_seq].seq_tag_b;
    if (expected_seq == 0)
        expected_seq = 1;
    while (g_sm->ring_buffer.node[current_seq].seq_tag_b >= expected_seq)
    {
        expected_seq = g_sm->ring_buffer.node[current_seq].seq_tag_b + 1;
        current_seq++;

        if (current_seq >= MAX_INSTRUMENT_NUM)
            current_seq = current_seq - NORMAL_INSTRUMENT_NUM;
    }

    if (current_seq >= NORMAL_INSTRUMENT_NUM)
        current_seq = current_seq - NORMAL_INSTRUMENT_NUM;
    return JXKR_MD_OK;
}

static void *run(void *args)
{
    instrument_t *ins;
    // printf("assignToThisCore %d \n", cfg->cpu_id);
    assignToThisCore(cpu_id);
    jxkr_prepare();
    // volatile uint64_t tick = 0;
    // volatile bool saved = access("./.debug", F_OK) != -1;
    // struct timespec tp, tmp;
    while (*pIsAlive)
    {
        ins = jxkr_next();
        if (ins != NULL)
        {
            // printf("ins %d %s", ins->snapTime, ins->instrumentId);
            callback(ins);
        }
    }

    return NULL;
}

jxkr_md_status_t jxkr_md_set_callback(void (*cb)(instrument_t *))
{
    CHECK_AUTH()
    callback = cb;
    if (callback == NULL)
        return JXKR_MD_PARAM_ERROR;
    return JXKR_MD_OK;
}

jxkr_md_status_t jxkr_md_loop(int cpuid, int *isAlive)
{
    CHECK_AUTH()
    cpu_id = cpuid;

    pIsAlive = isAlive;
    int res = pthread_create(&apiThread, NULL, run, g_sm);
    if (res != 0)
    {
        printf("pthread_create create failed %d\n", res);
        return JXKR_MD_THREAD_ERROR;
    }

    return JXKR_MD_OK;
}

jxkr_md_status_t jxkr_md_wait_for_loop()
{
    CHECK_AUTH()
    if (g_sm == NULL)
        return JXKR_MD_SHARED_MEMORY_ERROR;

    if (apiThread == 0)
        return JXKR_MD_THREAD_ERROR;
    pthread_join(apiThread, NULL);
    release_fpga_dma();
    return JXKR_MD_OK;
}

const char *jxkr_md_api_version()
{
    return API_VERSION;
}

jxkr_md_status_t jxkr_md_api_authorize(const char *ticket)
{
    char data[DATA_LENGH];
    int len = base64_decode(data, ticket);
    len -= sizeof(uint32_t);

    uint32_t crc1 = *((uint32_t *)&data[len]);
    uint32_t crc2 = crc32(data, len);

    uint8_t key[] = {0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab};
    uint8_t iv[] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, (uint8_t *)data, len);

    // check crc32
    if (crc1 != crc2)
        return JXKR_MD_TICKET_INVALID;

    // check expiration
    char now[9], endDate[9], mac[32];
    timestamp_day_str(time(NULL), now, sizeof(now));
    sscanf(data, "%s %s %s", endDate, endDate, mac);
    if (strcmp(now, endDate) > 0)
        return JXKR_MD_TICKET_EXPRIED;

    // check if MAC found
    if (check_mac(mac) != 0)
        return JXKR_MD_TICKET_NO_MAC_MATCHED;

    authroized = true;
    return JXKR_MD_OK;
}

jxkr_md_status_t jxkr_init_hq_board(char *confName)
{
    CHECK_AUTH()
    int r = init_fpga(confName);
    if (r != 0)
        return r + JXKR_MD_FPGA_ERROR;

    g_sm = (sm_shared_t *)config_fpga_dma();
    if (g_sm == NULL)
        return JXKR_MD_SHARED_MEMORY_ERROR;
    return JXKR_MD_OK;
}
