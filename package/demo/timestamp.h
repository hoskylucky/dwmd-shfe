#include <semaphore.h>
#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#define LONGLONG uint64_t

#define _loadlib(lib) dlopen(lib, RTLD_NOW)
#define _freelib(lib) dlclose(lib)
#define _getaddr(lib, func) dlsym(lib, func)
#define _liberr dlerror()

typedef void* (*init_dev)(const char* name);
static init_dev g_init_dev = 0;

typedef LONGLONG (*get_timestamp_x10)(void* dev);
static get_timestamp_x10 g_get_timestamp = 0;

typedef void(*deinit_dev)(void* dev);
static deinit_dev g_deinit_dev = 0;

static void* g_exanic_dev = 0;

inline LONGLONG get_freq()
{
	return 1000000000;
}

#define CPU_HZ 2200

typedef union {
	uint64_t tsc_64;
	__extension__
	struct
	{
		uint32_t lo_32;
		uint32_t hi_32;
	};
} tsc_t;

static unsigned int my_cpuid()
{
    /* ecx is often an input as well as an output. */
    unsigned int eax;
    unsigned int ebx;
    unsigned int ecx;
    unsigned int edx;
    eax = 0;
    ecx = 0;
    asm volatile("cpuid"
                 : "=a"(eax),
                   "=b"(ebx),
                   "=c"(ecx),
                   "=d"(edx)
                 : "0"(eax), "2"(ecx)
                 : "memory");
    return ebx;
}

__inline__ void rdtscb_getticks_s(tsc_t *ts) {
	asm volatile("rdtsc\n\t"
                 "mov %%edx, %0\n\t"
                 "mov %%eax, %1\n\t"
                 : "=r"(ts->hi_32), "=r"(ts->lo_32)::"%rax", "%rbx", "%rcx", "%rdx", "memory");
}

__inline__ void rdtscb_gettick_ordered(tsc_t *ts) {
	asm volatile("cpuid\n\t"
				 "rdtsc\n\t"
                 "mov %%edx, %0\n\t"
                 "mov %%eax, %1\n\t"
                 : "=r"(ts->hi_32), "=r"(ts->lo_32)::"%rax", "%rbx", "%rcx", "%rdx", "memory");
}


static LONGLONG get_fcount()
{
	if (g_get_timestamp && g_exanic_dev)
		return g_get_timestamp(g_exanic_dev);

	struct timespec tp;
	clock_gettime(CLOCK_REALTIME, &tp);
	return (LONGLONG)tp.tv_sec * 1000000000 + tp.tv_nsec;
}

static void init_timestamp(const char* dev)
{
	static void* g_lib = 0;
	if (!g_lib)
	{
		g_lib = _loadlib("libexanict.so");
		if (g_lib)
		{
			g_init_dev = (init_dev)_getaddr(g_lib, "init_exanic");
			g_get_timestamp = (get_timestamp_x10)_getaddr(g_lib, "get_tick");
			g_deinit_dev = (deinit_dev)_getaddr(g_lib, "deinit_exanic");

			if (g_init_dev)
			{
				g_exanic_dev = g_init_dev(dev);
			}
			else
				printf("--->>> g_init_dev failed %s\n", _liberr);
		}
		else
			printf("--->>> init_timestamp failed %s\n", _liberr);
	}
}