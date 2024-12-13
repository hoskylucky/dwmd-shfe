
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
    #ifndef _XOPEN_SOURCE
        #define _XOPEN_SOURCE
    #endif
    #include <sys/mman.h>
#endif

#include "shared_mem.h"

static void* smPtr = NULL;

/**
 * @brief
 *
 * @param mode   0 for read 1 for write
 * @return char*
 */
void*
config_fpga_dma() {
    if(smPtr == NULL) {
        if((access("/dev/hugepages/c2h_huge_page", F_OK)) == -1) {
            int fd = shm_open("/dev/hugepages/c2h_huge_page", O_CREAT | O_RDWR, 0777);
            if(fd > 0) {
                ftruncate(fd, sizeof(sm_shared_t));
                smPtr = mmap(NULL, sizeof(sm_shared_t), PROT_WRITE, MAP_SHARED, fd, 0);
                close(fd);
            }
        } else {

            // int fd = shm_open("/dev/hugepages/c2h_huge_page", O_RDWR, 0777);
            int fd = open("/dev/hugepages/c2h_huge_page", O_RDWR);
            if(fd > 0) {
                smPtr = mmap(NULL, sizeof(sm_shared_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
                close(fd);
            }
        }
    }
    return smPtr;
}

/**
 * @brief unmap the shared memory
 *
 */
void
release_fpga_dma() {
    if(smPtr) {
        munmap(smPtr, sizeof(sm_shared_t));
        smPtr = NULL;
    }
}
