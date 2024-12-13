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

FILE* g_file = nullptr;
int g_alive = 1;

struct alignas(64) data_store {
    instrument_t* snap;
    LONGLONG timed;
} ;

#define MAX_DATA_LEN 2000

struct alignas(64) data_list {
    uint32_t index;
    data_store datas[MAX_DATA_LEN];
};

data_list g_buffer;

static inline void FastSecondToDate(const time_t unix_sec, struct tm* tm, int time_zone)
{
	static const int kHoursInDay = 24;
	static const int kMinutesInHour = 60;
	static const int kDaysFromUnixTime = 2472632;
	static const int kDaysFromYear = 153;
	static const int kMagicUnkonwnFirst = 146097;
	static const int kMagicUnkonwnSec = 1461;
	tm->tm_sec = unix_sec % kMinutesInHour;
	int i = (int)(unix_sec / kMinutesInHour);
	tm->tm_min = i % kMinutesInHour; //nn
	i /= kMinutesInHour;
	tm->tm_hour = (i + time_zone) % kHoursInDay; // hh
	tm->tm_mday = (i + time_zone) / kHoursInDay;
	int a = tm->tm_mday + kDaysFromUnixTime;
	int b = (a * 4 + 3) / kMagicUnkonwnFirst;
	int c = (-b * kMagicUnkonwnFirst) / 4 + a;
	int d = ((c * 4 + 3) / kMagicUnkonwnSec);
	int e = -d * kMagicUnkonwnSec;
	e = e / 4 + c;
	int m = (5 * e + 2) / kDaysFromYear;
	tm->tm_mday = -(kDaysFromYear * m + 2) / 5 + e + 1;
	tm->tm_mon = (-m / 10) * 12 + m + 3;
	tm->tm_year = b * 100 + d - 4800 + (m / 10);
}

time_t file_open_time = 0;
#ifndef MAX_RECORD_IN_CSV
#define MAX_RECORD_IN_CSV 5000000
#endif
uint32_t csv_records_in_file = 0;

static inline void write_file(data_store *ret, FILE *&fp_csv) {

    if (!ret)
    {
        if (fp_csv)
        {
            fclose(fp_csv);
            fp_csv = NULL;
        }
        return;
    }

    time_t time_now;
    time(&time_now);

    if (fp_csv && time_now > file_open_time + 3600)
    {
        fclose(fp_csv);
        fp_csv = NULL;
    }

    if (!fp_csv)
    {
        char file_name[4096];
        struct tm *tm_now = localtime(&time_now);

        sprintf(file_name, "jxkr_%04d%02d%02d_%02d%02d%02d.csv",
                tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday,
                tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);

        fp_csv = fopen(file_name, "w");

        if (!fp_csv)
        {
            return;
        }

        file_open_time = time_now;

        const char* title = "UpdateTime,UpdateMillisec,InstrumentId,LastPrice,"
        "Volume,Turnover,OpenInterest,UpperLimitPrice,LowerLimitPrice,AveragePrice,"
        "BidPrices,BidVolumes,AskPrices,AskVolumes\n";
        fprintf(fp_csv, title);
        fflush(fp_csv);
    }

    struct tm s_tm;
    FastSecondToDate(ret->snap->snapTime, &s_tm, 8);
    fprintf(fp_csv, "%u,%03d,%s,%.2f,%d,%.2f,%d,%lu,%llu,%lu,\"%.2f,%.2f,%.2f,%.2f,%.2f\",\"%d,%d,%d,%d,%d\",\"%.2f,%.2f,%.2f,%.2f,%.2f\",\"%d,%d,%d,%d,%d\"\n", 
            //s_tm.tm_hour, s_tm.tm_min, s_tm.tm_sec,
            ret->snap->snapTime,
            ret->snap->snapMillSec,
            ret->snap->instrumentId,
            ret->snap->lastPrice,
            ret->snap->volume,
            ret->snap->turnover,
            ret->snap->openInterest,
            ret->timed & 0xFFFFFFFF,
            (ret->timed & 0xFFFFFFFF00000000ULL) >> 32,
            0,
            ret->snap->bidPrice[0], ret->snap->bidPrice[1], ret->snap->bidPrice[2], 
            ret->snap->bidPrice[3], ret->snap->bidPrice[4],

            ret->snap->bidVol[0], ret->snap->bidVol[1], ret->snap->bidVol[2], 
            ret->snap->bidVol[3], ret->snap->bidVol[4],

            ret->snap->askPrice[0], ret->snap->askPrice[1], ret->snap->askPrice[2], 
            ret->snap->askPrice[3], ret->snap->askPrice[4],

            ret->snap->askVol[0], ret->snap->askVol[1], ret->snap->askVol[2], 
            ret->snap->askVol[3], ret->snap->askVol[4]
            );

    fflush(fp_csv);

    csv_records_in_file++;
    if (csv_records_in_file >= MAX_RECORD_IN_CSV)
    {
        fclose(fp_csv);
        fp_csv = NULL;
        csv_records_in_file = 0;
    }
}

uint64_t last_mq_ts = 0, tsc_now = 0, tsc_last_tick = 0;

uint64_t CPU_FREQ_MHZ = 2200;
uint64_t IDLE_INTERVAL_MQ = CPU_FREQ_MHZ * 100 * 5;
uint64_t IDLE_INTERVAL_TICK_START = CPU_FREQ_MHZ * 1000 * 50;
uint64_t IDLE_INTERVAL_TICK_STOP = CPU_FREQ_MHZ * 1000 * 200;
uint64_t INTERVAL_100MS = CPU_FREQ_MHZ * 1000 * 100;
uint64_t INTERVAL_150MS = CPU_FREQ_MHZ * 1000 * 150;
uint64_t INTERVAL_250MS = CPU_FREQ_MHZ * 1000 * 250;
// uint64_t INTERVAL_500MS = CPU_FREQ_MHZ * 1000 * 500;
uint64_t INTERVAL_1000MS = CPU_FREQ_MHZ * 1000 * 1000;

void user_md_handler(instrument_t*md) {
    if (md == NULL) return;
    tsc_t timed;
    rdtscb_getticks_s (&timed);
    tsc_now = timed.tsc_64;
    g_buffer.datas[g_buffer.index].snap = md;
    g_buffer.datas[g_buffer.index].timed = timed.tsc_64;
    g_buffer.index++;

    if (tsc_last_tick < tsc_now - INTERVAL_150MS) {
        tsc_last_tick = tsc_now;
    }
    last_mq_ts = tsc_now;
}

void user_free_handler() {

    tsc_t timed;
    rdtscb_getticks (&timed);
    if (timed.tsc_64 - last_mq_ts >= IDLE_INTERVAL_MQ &&
        (timed.tsc_64 - tsc_last_tick) % INTERVAL_250MS >= IDLE_INTERVAL_TICK_START &&
        (timed.tsc_64 - tsc_last_tick) % INTERVAL_250MS < IDLE_INTERVAL_TICK_STOP)
    {
        if (g_buffer.index > 0) {
            for (uint32_t i = 0; i < g_buffer.index; ++i) {
                write_file(&g_buffer.datas[i], g_file);
            }
            g_buffer.index = 0;
        }
    }
}

void kill_hnd(int sig)
{
    printf("kill_hnd %d\n", sig);
    g_alive = 0;
}

static void assignToThisCore(int core_id)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core_id, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
}

#pragma pack(push, 8)

#define NORMAL_INSTRUMENT_NUM 4096
#define MAX_INSTRUMENT_NUM NORMAL_INSTRUMENT_NUM + 1638

// 32
typedef struct sm_header
{
    uint32_t magic_number; // 0xD57A0BEE
    uint16_t reserved1;
    uint16_t instruments_number; // 4096
    uint16_t state_len;          // length of market state  8
    uint16_t ring_buffer_len;    // length of ring buffer  8
    uint32_t content_length;
    double reserved2; // TODO:
    double reserved3; // TODO:
}__attribute__((__packed__))sm_header_t;

typedef struct ring_node
{
    char reserved[4];
    instrument_t snap;
    uint32_t seq_tag;
}__attribute__((__packed__)) ring_node_t;

typedef struct ring_buffer
{
    ring_node_t node[MAX_INSTRUMENT_NUM];
}__attribute__((__packed__))ring_buffer_t;

// 
typedef struct market_state
{
    uint8_t state; // 0 not write 1 writed
    uint8_t reserved1;
    uint16_t reserved2;
    uint32_t reserved3;   // used to save expected_seq for lib
    uint64_t reserved[3]; // TODO: may not necessary
}__attribute__((__packed__))market_state_t;

typedef struct sm_shared
{
    sm_header_t header;
    market_state_t state;
    ring_buffer_t ring_buffer;
}__attribute__((__packed__))sm_shared_t;

#pragma pack(pop)

#include <sys/mman.h>
#include <fcntl.h>

static void *smPtr = NULL;

void *config_fpga_dma()
{
    if (smPtr == NULL)
    {
        if ((access("/dev/hugepages/c2h_huge_page", F_OK)) == -1)
        {
            int fd = shm_open("/dev/hugepages/c2h_huge_page", O_CREAT | O_RDWR, 0777);
            if (fd > 0)
            {
                ftruncate(fd, sizeof(sm_shared_t));
                smPtr = mmap(NULL, sizeof(sm_shared_t), PROT_WRITE, MAP_SHARED, fd, 0);
                close(fd);
            }
        }
        else
        {
	    
            //int fd = shm_open("/dev/hugepages/c2h_huge_page", O_RDWR, 0777);
            printf("*******************\n");
            int fd = open("/dev/hugepages/c2h_huge_page", O_RDWR);
            if (fd > 0)
            {
                smPtr = mmap(NULL, sizeof(sm_shared_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
                close(fd);
            }
        }
    }
    return smPtr;
}

static void run(int cpu_id)
{
    sm_shared_t *sm = (sm_shared_t *)config_fpga_dma();

    volatile uint64_t current_seq = 0;
    instrument_t* ins;
    
    assignToThisCore(cpu_id);

    if (sm->state.reserved3 == 0)
        sm->state.reserved3 = 1;

   // volatile uint64_t expected_seq = sm->state.reserved3;
    uint64_t expected_seq = sm->ring_buffer.node[current_seq].seq_tag;
    if (expected_seq == 0) expected_seq = 1;
    while (sm->ring_buffer.node[current_seq].seq_tag >= expected_seq) {
        expected_seq = sm->ring_buffer.node[current_seq].seq_tag + 1;
        current_seq++;
        
        if (current_seq >= MAX_INSTRUMENT_NUM)
            current_seq = current_seq - NORMAL_INSTRUMENT_NUM;
    }

    if (current_seq >= NORMAL_INSTRUMENT_NUM)
        current_seq = current_seq - NORMAL_INSTRUMENT_NUM;

    bool last_buzy = false, buzy;
    while (g_alive)
    {
        buzy = false;
        for (int i = 0; i < 1000; ++i) {
            last_buzy = buzy;
            if (sm->ring_buffer.node[current_seq].seq_tag != expected_seq) {

                if (current_seq >= NORMAL_INSTRUMENT_NUM)
                    current_seq = current_seq - NORMAL_INSTRUMENT_NUM;
                buzy = false;
                if (!last_buzy) {

                    tsc_t timed;
                    rdtscb_getticks_s (&timed);
                    if (timed.tsc_64 - last_mq_ts >= IDLE_INTERVAL_MQ &&
                        (timed.tsc_64 - tsc_last_tick) % INTERVAL_250MS >= IDLE_INTERVAL_TICK_START &&
                        (timed.tsc_64 - tsc_last_tick) % INTERVAL_250MS < IDLE_INTERVAL_TICK_STOP)
                    {
                        if (g_buffer.index > 0) {
                            for (uint32_t i = 0; i < g_buffer.index; ++i) {
                                write_file(&g_buffer.datas[i], g_file);
                            }
                            g_buffer.index = 0;
                        }
                    }
                    
                    break;
                }
            }
            else
            {
                ins = &sm->ring_buffer.node[current_seq].snap;
                // if (strlen(ins->instrumentId) <= 6) 
                {
                    tsc_t timed;
                    rdtscb_getticks_s (&timed);
                    tsc_now = timed.tsc_64;
                    g_buffer.datas[g_buffer.index].snap = ins;
                    g_buffer.datas[g_buffer.index].timed = timed.tsc_64;
                    g_buffer.index++;

                    if (tsc_last_tick < tsc_now - INTERVAL_150MS) {
                        tsc_last_tick = tsc_now;
                    }
                    last_mq_ts = tsc_now;
                }
                expected_seq++;
                
                current_seq++;
                if (current_seq >= MAX_INSTRUMENT_NUM)
                    current_seq = current_seq - NORMAL_INSTRUMENT_NUM;
                buzy = true;
            }
        }
        
    }
}

const char * auth_code = "uhQ3BlL1h1PMXC4DCtbSpId/vSsqaLTIyyw6OZEbexfZyLjX4XVHtJHGR4RaHwEG9JgPjw==";

int main(int argc, const char *args[]) {

    sm_shared_t sm;
    FILE *ptr;
    ptr = fopen("../shared_mem.dat", "rb");
    printf("%lld\n", fread(&sm, sizeof(sm_shared_t), 1, ptr));
    fclose(ptr);
    
    for (auto i = 0; i < MAX_INSTRUMENT_NUM; i++) {
        ring_node_t* r = &sm.ring_buffer.node[i];
        printf("%lld, %lld %s\n", i, r->seq_tag, r->snap.instrumentId); 
    }

    int cpu = 8;
    if (argc > 1) cpu = atoi(args[1]);
    if (cpu == 0) cpu = 8;

    if (argc > 2 && strcmp(args[2], "init")) {
        // 认证板卡
        jxkr_md_status_t s = jxkr_md_api_authorize(auth_code);
        if (s != JXKR_MD_OK) {
            printf("auth failed %d\n", s);
            return s;
        }

        // 初始化板卡
        char cfg[] = "/opt/hq100/conf/md-config.ini";
        s = jxkr_init_hq_board(cfg);
        if (s != JXKR_MD_OK) {
            printf("auth failed %d\n", s);
            return s;
        }
    }

    signal(SIGRTMIN + 1, kill_hnd);
    run(cpu);
    printf("done");
    return 0;
}