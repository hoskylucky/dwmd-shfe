#include "jxkr_mdapi.h"
#include "iniparser.h"
#include "shared_mem.h"
#include "tsd_mdapi.h"
#include "version.h"
#include <fmt/format.h>
#include <lcxx/identifiers/hardware.hpp>
#include <lcxx/identifiers/os.hpp>
#include <lcxx/lcxx.hpp>
#include <pthread.h>
#include <spdlog/spdlog.h>

#define DATA_LENGH 256

static std::string APP_VERSION =
    fmt::format("v{}.{}.{}", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);

#define API_VERSION "v2.4"

#define CHECK_AUTH() \
    if(!authroized) return JXKR_MD_NOT_AUTHORIZED;

// #define CHECK_AUTH() ;

static void (*callback)(instrument_t*) = NULL;
static pthread_t apiThread = 0;
static int cpu_id = 0;
static bool authroized = false;
static int* pIsAlive;
static sm_shared_t* g_sm = NULL;

static void
assignToThisCore(int core_id) {
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

instrument_t*
jxkr_next() {
    instrument_t* res = NULL;
    if(g_sm->ring_buffer.node[current_seq].seq_tag_b != expected_seq) {
        if(current_seq >= NORMAL_INSTRUMENT_NUM) current_seq = current_seq - NORMAL_INSTRUMENT_NUM;

        // if (g_sm->ring_buffer.node[current_seq].seq_tag_b != 0 && !file_saved)
        // {
        //     printf("saved %ld %u %ld \n", current_seq,
        //     g_sm->ring_buffer.node[current_seq].seq_tag_b, expected_seq); printf("size %lu %lu
        //     %lu %lu \n", sizeof(sm_shared_t), sizeof(sm_header_t), sizeof(ring_node_t),
        //     sizeof(instrument_t)); file_saved = true; FILE *f = fopen("./mem.dat", "wb");
        //     fwrite(g_sm, sizeof(sm_shared_t), 1, f);
        //     fclose(f);
        //     printf("saved");
        // }
    } else {
        res = &g_sm->ring_buffer.node[current_seq].snap;
        expected_seq++;
        current_seq += 1;
        if(current_seq >= MAX_INSTRUMENT_NUM) current_seq = current_seq - NORMAL_INSTRUMENT_NUM;
    }
    return res;
}

jxkr_md_status_t
jxkr_prepare() {
    if(g_sm == NULL) return JXKR_MD_SHARED_MEMORY_ERROR;
    expected_seq = g_sm->ring_buffer.node[current_seq].seq_tag_b;
    if(expected_seq == 0) expected_seq = 1;
    while(g_sm->ring_buffer.node[current_seq].seq_tag_b >= expected_seq) {
        expected_seq = g_sm->ring_buffer.node[current_seq].seq_tag_b + 1;
        current_seq += 1;

        if(current_seq >= MAX_INSTRUMENT_NUM) current_seq = current_seq - NORMAL_INSTRUMENT_NUM;
    }

    if(current_seq >= NORMAL_INSTRUMENT_NUM) current_seq = current_seq - NORMAL_INSTRUMENT_NUM;
    return JXKR_MD_OK;
}

static void*
run(void* args) {
    instrument_t* ins;
    // printf("assignToThisCore %d \n", cfg->cpu_id);
    assignToThisCore(cpu_id);
    jxkr_prepare();
    // volatile uint64_t tick = 0;
    // volatile bool saved = access("./.debug", F_OK) != -1;
    // struct timespec tp, tmp;
    while(*pIsAlive) {
        ins = jxkr_next();
        if(ins != NULL) {
            // printf("ins %d %s", ins->snapTime, ins->instrumentId);
            callback(ins);
        }
    }

    return NULL;
}

jxkr_md_status_t
jxkr_md_set_callback(void (*cb)(instrument_t*)) {
    CHECK_AUTH()
    callback = cb;
    if(callback == NULL) return JXKR_MD_PARAM_ERROR;
    return JXKR_MD_OK;
}

jxkr_md_status_t
jxkr_md_loop(int cpuid, int* isAlive) {
    CHECK_AUTH()
    cpu_id = cpuid;

    pIsAlive = isAlive;
    int res = pthread_create(&apiThread, NULL, run, g_sm);
    if(res != 0) {
        spdlog::error("pthread_create create failed %d\n", res);
        return JXKR_MD_THREAD_ERROR;
    }

    return JXKR_MD_OK;
}

jxkr_md_status_t
jxkr_md_wait_for_loop() {
    CHECK_AUTH()
    if(g_sm == NULL) return JXKR_MD_SHARED_MEMORY_ERROR;

    if(apiThread == 0) return JXKR_MD_THREAD_ERROR;
    pthread_join(apiThread, NULL);
    release_fpga_dma();
    return JXKR_MD_OK;
}

const char*
jxkr_md_api_version() {
    return APP_VERSION.c_str();
}

constexpr auto public_key = R"(
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnR/pV5N+Nv9WcYIlwJTN3Lp2w
4LHo9GCQJKnmBP8Ch7ouqKCJ+LmRlU0VoCLlN76JXxjAtpcOLbrZrNZQR5OlcgC9
pONBNimQkQgGQWzqN9EA3GhHcMrkUg+ddRO0lBE9eJ0IomBKfwIFOvrbaMwVYX6y
AnNbulUgSaBk16G41QIDAQAB
-----END PUBLIC KEY-----
)";

jxkr_md_status_t
jxkr_md_api_authorize(const char* filename) {
    using namespace lcxx::experimental::identifiers;

    auto print_identity = []() {
        using namespace lcxx::experimental::identifiers;
        spdlog::error("This license is invalid! identity hash {}:{}", hardware().hash, os().hash);
    };
    if(!std::filesystem::exists(filename)) {
        print_identity();
        return JXKR_MD_NOT_AUTHORIZED;
    }

    auto key = lcxx::crypto::load_key(std::string(public_key), lcxx::crypto::key_type::public_key);
    auto [license, signature] = lcxx::from_json(std::filesystem::path(filename));

    if(!lcxx::verify_license(license, signature, key)) {
        print_identity();
        return JXKR_MD_NOT_AUTHORIZED;
    }

    if(auto s = license.get("hardware"); !s || !verify(hw_ident_strat::all, s.value())) {
        print_identity();
        return JXKR_MD_NOT_AUTHORIZED;
    }

    if(auto s = license.get("os"); !s || !verify(os_ident_strat::all, s.value())) {
        print_identity();
        return JXKR_MD_NOT_AUTHORIZED;
    }

    if(auto s = license.get("date"); !s) {
        print_identity();
        return JXKR_MD_NOT_AUTHORIZED;
    } else {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm buf;
        localtime_r(&in_time_t, &buf);
        char current_date[9];
        strftime(current_date, sizeof(current_date), "%Y%m%d", &buf);

        if(std::string(current_date) > s.value()) {
            print_identity();
            return JXKR_MD_NOT_AUTHORIZED;
        }
    }

    authroized = true;
    return JXKR_MD_OK;
}

int
jxkr_init_hq_board(char* confName, quote_mode_t mode) {
    CHECK_AUTH()
    if(mode == QM_MASTER) {
        int r = init_fpga(confName);
        if(r != 0) return r + JXKR_MD_FPGA_ERROR;
        spdlog::info("board is running in master mode\n");
    }

    g_sm = (sm_shared_t*)config_fpga_dma();
    if(g_sm == NULL) return JXKR_MD_SHARED_MEMORY_ERROR;
    return JXKR_MD_OK;
}
