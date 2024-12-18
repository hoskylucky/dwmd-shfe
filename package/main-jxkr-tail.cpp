#include "../include/jxkr_mdapi.h"
#include <atomic>
#include <deque>
#include <iostream>
#include <mutex>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <string>
#include <thread>
#include <unordered_map>

typedef std::unordered_map<std::string, FILE*> fp_map_t;
sem_t qsem;

int g_alive = 1;

typedef struct __data_store {
    instrument_t snap;
    uint64_t timed;
} data_store;

std::deque<data_store*> g_queue;
std::mutex g_mux;

static int keep_running = 1;

// api回调
void
user_md_handler(instrument_t* md) {
    if(md == NULL) return;
    data_store* snap = (data_store*)malloc(sizeof(data_store));
    snap->snap = *md;
    // 通知写线程
    {
        std::lock_guard<std::mutex> lock(g_mux);
        g_queue.push_back(snap);
    }
    sem_post(&qsem);
}

// 结束进程通知线程
void
kill_hnd(int sig) {
    printf("kill_hnd %d\n", sig);
    sem_post(&qsem);
}

int
main() {

    // 认证板卡
    jxkr_md_status_t s = jxkr_md_api_authorize("license.lic");
    if(s != JXKR_MD_OK) {
        printf("auth failed %d\n", s);
        return s;
    }

    signal(SIGINT, kill_hnd);
    signal(SIGTERM, kill_hnd);
    // signal(SIGRTMIN + 1, kill_hnd);

    sem_init(&qsem, 0, 0);

    std::thread t([] {
        data_store* ret = NULL;
        char data[1024];

        // 待写入的文件
        FILE* ptr;
        ptr = fopen("./cache/data.csv", "wb");
        const char* title = "UpdateTime,UpdateMillisec,InstrumentId,LastPrice,Volume,Turnover,"
                            "OpenInterest,UpperLimitPrice,LowerLimitPrice,AveragePrice,BidPrices,"
                            "BidVolumes,AskPrices,AskVolumes\n";
        fwrite(title, strlen(title), 1, ptr);

        while(sem_wait(&qsem) == 0) {
            {
                std::lock_guard<std::mutex> lock(g_mux);
                ret = g_queue.front();
                g_queue.pop_front();
            }
            if(ret == NULL) break;

            sprintf(data,
                    "%d,%03d,%s,%.2f,%d,%.2f,%d,%lu,%llu,%u,\"%.2f,%.2f,%.2f,%.2f,%.2f\",\"%d,%d,%"
                    "d,%d,%d\",\"%.2f,%.2f,%.2f,%.2f,%.2f\",\"%d,%d,%d,%d,%d\"\n",
                    ret->snap.snapTime,
                    ret->snap.snapMillSec,
                    ret->snap.instrumentId,
                    ret->snap.lastPrice,
                    ret->snap.volume,
                    ret->snap.turnover,
                    ret->snap.openInterest,
                    ret->timed & 0xFFFFFFFF,
                    (ret->timed & 0xFFFFFFFF00000000ULL) >> 32,
                    0,
                    ret->snap.bidPrice[0],
                    ret->snap.bidPrice[1],
                    ret->snap.bidPrice[2],
                    ret->snap.bidPrice[3],
                    ret->snap.bidPrice[4],

                    ret->snap.bidVol[0],
                    ret->snap.bidVol[1],
                    ret->snap.bidVol[2],
                    ret->snap.bidVol[3],
                    ret->snap.bidVol[4],

                    ret->snap.askPrice[0],
                    ret->snap.askPrice[1],
                    ret->snap.askPrice[2],
                    ret->snap.askPrice[3],
                    ret->snap.askPrice[4],

                    ret->snap.askVol[0],
                    ret->snap.askVol[1],
                    ret->snap.askVol[2],
                    ret->snap.askVol[3],
                    ret->snap.askVol[4]);
            fwrite(data, strlen(data), 1, ptr);
            free(ret);
        }
        printf("done ");

        fclose(ptr);

        keep_running = 0;
    });

    // 初始化板卡 如果是旁路，则不需要初始化板卡
    char cfg[] = "/opt/hq100/conf/md-config.ini";
    if(jxkr_init_hq_board(cfg, QM_MASTER) != JXKR_MD_OK) {
        printf("auth failed %d\n", s);
        return -1;
    }

    // 注册回调
    jxkr_md_set_callback(user_md_handler);

    // 启动api线程
    jxkr_md_status_t res = jxkr_md_loop(10, &g_alive);
    if(res != JXKR_MD_OK) printf("jxkr_fpga start error %d\n", res);
    else printf("jxkr_fpga start succ %s\n", jxkr_md_api_version());

    t.join();
    printf("done");
    return 0;
}
