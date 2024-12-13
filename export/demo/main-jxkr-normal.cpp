#include "../inc/jxkr_mdapi.h"
#include "timestamp.h"

#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <semaphore.h>
#include <pthread.h>
#include <unordered_map>
#include <string>
#include <atomic>
#include <iostream>
#include <thread>

typedef std::unordered_map<std::string, FILE *> fp_map_t;
sem_t qsem;

int g_alive = 1;

typedef struct __data_store
{
    char instrumentId[16];
    uint32_t snapTime; // sec num
    uint16_t snapMillSec;
    LONGLONG timed;
} data_store;

#define MAX_DATA_LEN 120000

typedef struct __data_list
{
    data_store datas[MAX_DATA_LEN];
    uint32_t index;
} data_list;

typedef struct __double_buffer
{
    data_list left, right;
    std::atomic_bool side; // true for left otherwise right
} double_buffer;

double_buffer g_buffer;

static inline void push(instrument_t *inst, LONGLONG timed)
{

    data_list *lst = g_buffer.side ? &g_buffer.left : &g_buffer.right;
    data_store *ds = &lst->datas[lst->index];
    memcpy(&ds->instrumentId, inst->instrumentId, sizeof(inst->instrumentId));
    ds->snapTime = inst->snapTime;
    ds->snapMillSec = inst->snapMillSec;

    // snprintf(ds->symbol, sizeof(ds->symbol), "%s", symbol);
    ds->timed = timed;

    lst->index++;
    if (lst->index == MAX_DATA_LEN)
    {
        g_buffer.side = !g_buffer.side;
        sem_post(&qsem);
    }
}

static inline uint32_t dump_store(fp_map_t *m)
{
    data_store *ret = NULL;
    char data[1024];

    FILE *ptr;
    if (m->empty())
    {
        ptr = fopen("./cache/data.csv", "wb");
        const char *title = "UpdateTime,UpdateMillisec,InstrumentId,LocalTime\n";
        fwrite(title, strlen(title), 1, ptr);
        m->operator[]("s") = ptr;
    }
    else
    {
        ptr = m->begin()->second;
    }
    data_list *lst = g_buffer.side ? &g_buffer.right : &g_buffer.left;

    for (uint32_t i = 0; i < lst->index; ++i)
    {
        ret = &lst->datas[i];
        sprintf(data, "%d,%03d,%s,%llu\n",
                ret->snapTime,
                ret->snapMillSec,
                ret->instrumentId,
                ret->timed);
        fwrite(data, strlen(data), 1, ptr);
    }
    uint32_t res = lst->index;
    lst->index = 0;
    fflush(ptr);
    return res;
}

void user_md_handler(instrument_t *md)
{
    if (md == NULL)
        return;
    tsc_t timed;
    rdtscb_getticks_s(&timed);
    push(md, timed.tsc_64);
}

void kill_hnd(int sig)
{
    printf("kill_hnd %d\n", sig);
    g_buffer.side = !g_buffer.side;
    sem_post(&qsem);
}

// 认证码
const char *auth_code = "J5N+wY30d7wQ8iYxFv8lHiIF0Ih6vcUeRo19eSx+rUK/5kDQJy3E5hsae+HHsJFbQBAewg==";

int main()
{

    // 认证板卡
    jxkr_md_status_t s = jxkr_md_api_authorize(auth_code);
    if (s != JXKR_MD_OK)
    {
        printf("auth failed %d\n", s);
        return s;
    }

    signal(SIGRTMIN + 1, kill_hnd);

    sem_init(&qsem, 0, 0);

    std::thread t([]
                  {
        fp_map_t m;

        while (sem_wait(&qsem) == 0) {
            auto n = dump_store(&m);
            if (n != MAX_DATA_LEN) break;
        }

        for (auto i = m.begin(); i != m.end(); i++) {
            fclose(i->second);
        } });

    // 初始化板卡
    char cfg[] = "/opt/hq100/conf/md-config.ini";
    s = jxkr_init_hq_board(cfg);
    if (s != JXKR_MD_OK)
    {
        printf("auth failed %d\n", s);
        return s;
    }

    jxkr_md_set_callback(user_md_handler);

    jxkr_md_status_t res = jxkr_md_loop(10, &g_alive);
    if (res != JXKR_MD_OK)
    {
        printf("jxkr_fpga start error %d\n", res);
    }
    else
        printf("jxkr_fpga start succ %s\n", jxkr_md_api_version());

    t.join();
    printf("done");
    return 0;
}
