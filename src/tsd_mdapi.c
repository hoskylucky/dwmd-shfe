#include "tsd_mdapi.h"
#include "iniparser.h"
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define TSD_RUN_PATH "/var/run/tsd_run"
#define ERR_LOG_PATH "tsd_log"
// #define TSD_RUN_CONFIG  "tsd_conf"

#define MDQP_BASE_ADDR         0x200
#define MDQP_TCP_CHECK_SUM_REG 0x30
#define MDQP_TIMOUT_DOWN       0x38

#define MIRP_ABASE_ADDR 0x300
#define MIRP_BBASE_ADDR 0x380

#define MIRP_CBASE_ADDR 0x400
#define MIRP_DBASE_ADDR 0x480

#define MIRP_TABBASE_ADDR 0x3c
#define MIRP_TCDBASE_ADDR 0x48

#define CONF_BOARD_MODEAB_REG 0x34

#define VERSION_REG             0x0
#define COMPILE_REG             0x4
#define FPGA_ABTCP_PKTCOUNT_REG 0x800
#define FPGA_CDTCP_PKTCOUNT_REG 0x804
#define FPGA_AUDP_VALID_REG     0x808
#define FPGA_BUDP_VALID_REG     0x80c
#define FPGA_CUDP_VALID_REG     0x810
#define FPGA_DUDP_VALID_REG     0x814
#define SH2PS_1000_UDP_AREG     0x818
#define SH2PS_2000_UDP_AREG     0x81c
#define INE_UDP_AREG            0x820
#define SH2PS_1000_UDP_BREG     0x824
#define SH2PS_2000_UDP_BREG     0x828
#define INE_UDP_BREG            0x82c
#define SH2PS_1000_UDP_CREG     0x830
#define SH2PS_2000_UDP_CREG     0x834
#define INE_UDP_CREG            0x838
#define SH2PS_1000_UDP_DREG     0x83c
#define SH2PS_2000_UDP_DREG     0x840
#define INE_UDP_DREG            0x844
#define DMA_UPLOAD_COUNT_REG    0x900
#define NET_LINK_STU_REG        0x880
#define AERR_CRC_PKT            0x884
#define BERR_CRC_PKT            0x888
#define CERR_CRC_PKT            0x88c
#define DERR_CRC_PKT            0x890

#define INSTRUMENT_AB_FILTER_ADDR 0x500

#define INSTRUMENTNO_COUNT 64
#define COFIG_NODE_MAX     8

#define PCIE_DMA_DST_ADDR_H 0x14
#define PCIE_DMA_DST_ADDR_L 0x10

#define FPGA_RESET_REG 0xC

#define DEVICE_BAR0_USR   "/dev/jxkrstbar0"
#define DEVICE_BAR1_CNTRL "/dev/jxkrstbar1"
#define MAP_BAR0_LEN      4096
#define MAP_BAR1_LEN      0x10000
#define MAP_BAR1_ENABLE   0x1004
#define MAP_BAR1_TXENABLE 0x10c0

#define HUGE_PAGE_MOUNT_PATH "/dev/hugepages"
#define HUGE_PAGE_C2H_NODE   "/dev/hugepages/c2h_huge_page"
#define HUG_PAGE_SIZE        0x200000

#define PAGE_MARET_STU_OFFSET 32
#define PAGE_RINGBUFF_OFFSET  64

#define RET_SUCESS         0
#define ERROR_OPEN_USER    0x5E01  // open bar0 space error
#define ERROR_MAP_USER     0x5E02  // mmap bar0 space error
#define ERROR_OPEN_PAGE    0x5E03  // open huge page err
#define ERROR_MAP_PAGE     0x5E04  // map huge page err
#define ERROR_CONFIG_ARGS  0x5E05  // ab/cd config args error not null
#define ERROR_CONFIG_MDPQA 0x5E06  // mdpq a set num greater than max count
#define ERROR_CALLOC       0x5E07
#define ERROR_CONFIG_MDPQC 0x5E08  // mdpq c set num greater than max count
// #define ERROR_CONFIG_MDPQD     0x5E09    // mdpq d set num greater than max count
#define ERROR_CONFIG_MIRPA         0x5E0A  // mirp a set num greater than max count
#define ERROR_CONFIG_MIRPB         0x5E0B  // mirp b set num greater than max count
#define ERROR_CONFIG_MIRPC         0x5E0C  // mirp c set num greater than max count
#define ERROR_CONFIG_MIRPD         0x5E0D  // mirp d set num greater than max count
#define ERROR_CONFIG_HYNOALIVE     0x5E0E  // instruments no alive
#define ERROR_MKDIR_PAGE           0x5E0F  // mkdir huge page err
#define ERROR_OPEN_PID             0x5E10  // open thread pid err
#define ERROR_THREAD_CREATE        0x5E11
#define ERROR_OPEN_BAR1            0x5E12
#define ERROR_MAP_BAR1             0x5E13
#define ERROR_INSTRUMENT_STYLE     0x5E14
#define ERROR_CONF_WRITE_FAIL      0x5E15
#define ERROR_CONF_TOPIC           0x5E16
#define ERROR_INICONF_LOAD         0x5E17
#define ERROR_INICONF_INFO         0x5E18
#define ERROR_INICONF_UPLOAD       0x5E19
#define ERROR_INICONF_TCP          0x5E1A
#define ERROR_INICONF_UDP          0x5E1B
#define ERROR_INICONF_TOPIC        0x5E1C
#define ERROR_INICONF_FILTER_EN    0x5E1D
#define ERROR_INICONF_FILTER_FILE  0x5E1E
#define ERROR_INICONF_FILTER_      0x5E1F
#define ERROR_INICONF_FILTER_CROSS 0x5E20

typedef struct __item_mdqp {
    uint32_t addr;
    uint16_t port;
    uint16_t reserved1;
    uint8_t porteEn_0;
    uint8_t reserved2;
    uint8_t porteEn_2;
    uint8_t reserved3;

} item_mdqp;

typedef struct __cfg_mdqp {
    uint32_t cfg_num;
    item_mdqp cfgs[16];

} cfg_mdqp;

typedef struct __item_mirp {
    uint32_t addr;
    uint16_t port;
    uint32_t topic;
    uint8_t porteEn_0;
    uint8_t porteEn_1;
    uint8_t porteEn_2;
    uint8_t porteEn_3;

} item_mirp;

typedef struct __cfg_mirp {
    uint32_t cfg_num;
    item_mirp cfgs[20];
} cfg_mirp;

void
check_dir_alive(char* path) {
    DIR* dir;
    dir = opendir(path);
    if(NULL == dir) mkdir(path, 0777);
    else closedir(dir);
}

#define LOG_FILE_MAX_SIZE 2 * 1024 * 1024

void
log_info(const char* fmt, ...) {
#ifdef DEBUG
    char outstr[128] = { 0 };
    time_t tim;
    va_list ap;
    struct tm* ptim;
    char info[512] = { 0 };
    char filename[512] = { 0 };
    struct stat file_stat;
    check_dir_alive(TSD_RUN_PATH);
    sprintf(filename, "%s/%s", TSD_RUN_PATH, ERR_LOG_PATH);
    if(access(filename, F_OK) == 0) {
        lstat(filename, &file_stat);
        if(file_stat.st_size > LOG_FILE_MAX_SIZE) truncate(filename, 0);
    }
    FILE* logfd = fopen(filename, "a+");
    if(NULL == logfd) return;
    time(&tim);
    ptim = localtime(&tim);
    strftime(outstr, sizeof(outstr), "%Y:%m:%d:%H:%M:%S", (const struct tm*)ptim);
    va_start(ap, fmt);
    sprintf(info, "%s:%s\n", outstr, fmt);
    vfprintf(logfd, info, ap);
    va_end(ap);
    fclose(logfd);
#endif
}

#if 0
const char head_conf[4][10]={"A","B","C","D"};

int tsd_net_set_conf(const char *head,unsigned int ip,unsigned int port,unsigned int topic){
	char filename[512]={0};
	FILE *pfd;
	check_dir_alive(TSD_RUN_PATH);
	sprintf(filename,"%s/%s",TSD_RUN_PATH,TSD_RUN_CONFIG);

	pfd=fopen(filename,"a+");
	if(NULL==pfd){
		return -1;
	}
	fprintf(pfd,"%01s:%08x:%05d:%04d\n",head,ip,port,topic);
	fclose(pfd);
	return 0;
}

int tsd_get_net_conf(monitor_union* monitor){
	char filename[512]={0};
	char filebuf[512]={0};
	FILE *pfd;
	char node_name[128]={0};
	unsigned int ip,port,topic;
	sprintf(filename,"%s/%s",TSD_RUN_PATH,TSD_RUN_CONFIG);
	if(access(filename,F_OK) != 0)
		return -1;
	pfd=fopen(filename,"r+");
	if(NULL==pfd){
		return -1;
	}
	do{
		if(fgets(filebuf,sizeof(filebuf),pfd) == NULL)
			break;
		sscanf(filebuf,"%1s:%8x:%5d:%4d",node_name,&ip,&port,&topic);
		printf("%s:%x:%d:%d\n",node_name,ip,port,topic);
	}while(1);
	fclose(pfd);
	return 0;
}

void tsd_conf_file_unlink(void){
	char filename[512]={0};
	sprintf(filename,"%s/%s",TSD_RUN_PATH,TSD_RUN_CONFIG);
	if(access(filename,F_OK) == 0)
		unlink(filename);
}
#endif
static void
write_le32(volatile unsigned char* dev, unsigned int addr, unsigned int data) {
    *(volatile unsigned int*)(dev + addr) = data;
    msync((void*)(dev + addr), 4, MS_SYNC | MS_INVALIDATE);
    usleep(10000);
}

static unsigned int
read_le32(volatile unsigned char* dev, unsigned int addr) {
    return *(volatile unsigned int*)(dev + addr);
}

/*12 1017*/

static int
align_pagesize(unsigned int len) {
    int n = getpagesize();
    return ((len + n - 1) & (~(n - 1)));
}

int
reg_write(unsigned char* addr, unsigned int offset, unsigned int val) {
    int retval = 0;
    write_le32(addr, offset, val);
    retval = read_le32(addr, offset);
    if(retval != val) return ERROR_CONF_WRITE_FAIL;
    return RET_SUCESS;
}

void
clear_bar_map(unsigned char* bar_addr, unsigned int addr, unsigned int int_count) {
    int i = 0;
    for(i = 0; i < int_count; i++) {
        write_le32(bar_addr, addr + i * 4, 0);
        log_info("addr:0x%x--Value=%d\n", addr + i * 4, 0);
    }
}

int32_t
config_topic(unsigned char* bar_addr, unsigned int* topic_id, unsigned int topic_count) {
    int i;
    unsigned int topic = 0;
    int ret;
    unsigned int aoffset = 0;
    unsigned int coffset = 0;
    unsigned int cflag = 0;
    unsigned int err_num = RET_SUCESS;
    for(i = 0; i < topic_count; i++) {
        cflag = 0;
        if(topic_id[i] == 1000) {
            topic = 0;
        } else if(topic_id[i] == 1001) {
            topic = 1;
        } else if(topic_id[i] == 5000) {
            topic = 2;
        } else if(topic_id[i] == 5001) {
            topic = 3;
        } else if(topic_id[i] == 2000) {
            topic = 4;
        } else if(topic_id[i] == 1101) {
            topic = 5;
            cflag = 1;
        } else if(topic_id[i] == 5101) {
            topic = 3;
            cflag = 1;
        } else {
            err_num = ERROR_CONF_TOPIC;
            goto err;
        }
        if(cflag) {
            ret = reg_write(bar_addr, MIRP_TCDBASE_ADDR + coffset, topic);
            if(ret != RET_SUCESS) {
                err_num = ret;
                goto err;
            }
            log_info("Topci C Addr=0x%x--Value topic=0x%x", MIRP_TCDBASE_ADDR + coffset, topic);
            coffset += 4;
        } else {
            ret = reg_write(bar_addr, MIRP_TABBASE_ADDR + aoffset, topic);
            if(ret != RET_SUCESS) {
                err_num = ret;
                goto err;
            }
            log_info("Topci Addr=0x%x--Value topic=0x%x", MIRP_TABBASE_ADDR + aoffset, topic);
            aoffset += 4;
        }
    }
err:
    return err_num;
}

int32_t
config_tcp(unsigned char* bar_addr, cfg_mdqp* pMdqp) {
    unsigned int err_num = RET_SUCESS;
    unsigned int cmdqp_post = 0, amdqp_post = 0;
    unsigned int channel_num_offset = 0;
    int ret;
    int i;
    if(NULL == pMdqp) return ERROR_CONFIG_ARGS;
    if(pMdqp->cfg_num > COFIG_NODE_MAX) {
        err_num = ERROR_CONFIG_MDPQA;
        goto err;
    }
    clear_bar_map(bar_addr, MDQP_BASE_ADDR, 32);
    // amdqp_post = pMdqp->cfg_num - 1;
    for(i = 0; i < pMdqp->cfg_num; i++) {
        if(pMdqp->cfgs[i].porteEn_2) {
            channel_num_offset = 16 * (4 + cmdqp_post);
            cmdqp_post++;
        } else {
            channel_num_offset = 16 * amdqp_post;
            amdqp_post++;
        }
#if 0
			ret = reg_write(bar_addr,MDQP_BASE_ADDR +	channel_num_offset,0xd);
			if(ret != RET_SUCESS){
				err_num=ret;
			  goto err;
			}

			log_info("TCP ADDR=%x--tim=%x",MDQP_BASE_ADDR +	channel_num_offset,0xd);

#endif
        ret = reg_write(bar_addr, MDQP_BASE_ADDR + channel_num_offset + 4, pMdqp->cfgs[i].addr);
        if(ret != RET_SUCESS) {
            err_num = ret;
            goto err;
        }
        log_info("TCP ADDR=0x%x--IP=0x%x",
                 MDQP_BASE_ADDR + channel_num_offset + 4,
                 pMdqp->cfgs[i].addr);
        ret = reg_write(bar_addr, MDQP_BASE_ADDR + channel_num_offset + 8, pMdqp->cfgs[i].port);
        if(ret != RET_SUCESS) {
            err_num = ret;
            goto err;
        }
        log_info("TCP ADDR=0x%x--PORT=0x%x",
                 MDQP_BASE_ADDR + channel_num_offset + 8,
                 pMdqp->cfgs[i].port);
        ret = reg_write(bar_addr, MDQP_BASE_ADDR + channel_num_offset + 0xc, 1);
        if(ret != RET_SUCESS) {
            err_num = ret;
            goto err;
        }
        log_info("TCP ADDR=0x%x--Enable=%d", MDQP_BASE_ADDR + channel_num_offset + 0xc, 1);
        if(pMdqp->cfgs[i].porteEn_2) {
            log_info("C TCP IP:%x,Port:%d,No:%d", pMdqp->cfgs[i].addr, pMdqp->cfgs[i].port, i);
            // tsd_net_set_conf("C",pMdqp->cfgs[i].addr,pMdqp->cfgs[i].port,0);
        } else {
            log_info("A TCP IP:%x,Port:%d,No:%d Addr=%x",
                     pMdqp->cfgs[i].addr,
                     pMdqp->cfgs[i].port,
                     i,
                     MDQP_BASE_ADDR);
            // tsd_net_set_conf("A",pMdqp->cfgs[i].addr,pMdqp->cfgs[i].port,0);
        }
    }

    if(pMdqp->cfg_num) {
        ret = reg_write(bar_addr, MDQP_TCP_CHECK_SUM_REG, 1);
        if(ret != RET_SUCESS) {
            err_num = ret;
            goto err;
        }
        log_info("MDQP_TCP_CHECK_SUM_REG ADDR0x=%x,Value=%d", MDQP_TCP_CHECK_SUM_REG, 1);

        ret = reg_write(bar_addr, MDQP_TIMOUT_DOWN, 0xd);
        if(ret != RET_SUCESS) {
            err_num = ret;
            goto err;
        }
        log_info("MDQP_TIMOUT_DOWN ADDR0x=%x,Value=%d", MDQP_TIMOUT_DOWN, 0xd);
    }

err:
    return err_num;
}

int32_t
config_udp(unsigned char* bar_addr, cfg_mirp* pMirp) {
    int i = 0;
    unsigned char anum = 0, bnum = 0, cnum = 0, dnum = 0;
    unsigned int apost = 0xff, bpost = 0xff, cpost = 0xff, dpost = 0xff;
    unsigned int err_num = RET_SUCESS;
    int ret = 0;
    unsigned int flag = 0;
    unsigned int offset = 0;
    if(NULL == pMirp) return ERROR_CONFIG_ARGS;
    clear_bar_map(bar_addr, MIRP_ABASE_ADDR, 16);
    clear_bar_map(bar_addr, MIRP_BBASE_ADDR, 16);
    clear_bar_map(bar_addr, MIRP_CBASE_ADDR, 16);
    clear_bar_map(bar_addr, MIRP_DBASE_ADDR, 16);
    for(i = 0; i < pMirp->cfg_num; i++) {
        if(pMirp->cfgs[i].porteEn_0) {
            if(anum > COFIG_NODE_MAX) {
                err_num = ERROR_CONFIG_MIRPA;
                goto err;
            }
            if((pMirp->cfgs[i].topic == 1000) || (pMirp->cfgs[i].topic == 1001)) {
                apost = 0;
                if(flag & 0x1) {
                    offset = apost * 16 + 8;
                    flag |= 0x2;
                } else {
                    offset = apost * 16;
                    flag |= 0x1;
                }
            } else if((pMirp->cfgs[i].topic == 5000) || (pMirp->cfgs[i].topic == 5001)) {
                apost = 1;
                if(flag & 0x4) {
                    offset = apost * 16 + 8;
                    flag |= 0x8;
                } else {
                    offset = apost * 16;
                    flag |= 0x4;
                }
            } else if(pMirp->cfgs[i].topic == 2000) {
                apost = 2;
                if(flag & 0x10) {
                    offset = apost * 16 + 8;
                    flag |= 0x20;
                } else {
                    offset = apost * 16;
                    flag |= 0x10;
                }
            } else {
                err_num = ERROR_CONF_TOPIC;
                goto err;
            }

            ret = reg_write(bar_addr, MIRP_ABASE_ADDR + offset, pMirp->cfgs[i].addr);
            if(ret != RET_SUCESS) {
                err_num = ret;
                goto err;
            }
            log_info("A UDP IP:0x%x,No:%d,Post=%d,ADDR=0x%x",
                     pMirp->cfgs[i].addr,
                     anum,
                     apost,
                     MIRP_ABASE_ADDR + offset);
            ret = reg_write(bar_addr, MIRP_ABASE_ADDR + offset + 4, pMirp->cfgs[i].port);
            if(ret != RET_SUCESS) {
                err_num = ret;
                goto err;
            }
            log_info("A UDP Port:%d,No:%d,Post=%d,ADDR=0x%x",
                     pMirp->cfgs[i].port,
                     anum,
                     apost,
                     MIRP_ABASE_ADDR + offset + 4);
            // tsd_net_set_conf("A",pMirp->cfgs[i].addr,pMirp->cfgs[i].port,pMirp->cfgs[i].topic);
            anum++;
        }
        if(pMirp->cfgs[i].porteEn_1) {

            if(bnum > COFIG_NODE_MAX) {
                err_num = ERROR_CONFIG_MIRPB;
                goto err;
            }

            if((pMirp->cfgs[i].topic == 1000) || (pMirp->cfgs[i].topic == 1001)) {
                bpost = 0;
                if(flag & 0x40) {
                    offset = bpost * 16 + 8;
                    flag |= 0x80;
                } else {
                    offset = bpost * 16;
                    flag |= 0x40;
                }
            } else if((pMirp->cfgs[i].topic == 5000) || (pMirp->cfgs[i].topic == 5001)) {
                bpost = 1;
                if(flag & 0x100) {
                    offset = bpost * 16 + 8;
                    flag |= 0x200;
                } else {
                    offset = bpost * 16;
                    flag |= 0x100;
                }
            } else if(pMirp->cfgs[i].topic == 2000) {
                bpost = 2;
                if(flag & 0x400) {
                    offset = bpost * 16 + 8;
                    flag |= 0x800;
                } else {
                    offset = bpost * 16;
                    flag |= 0x400;
                }
            } else {
                err_num = ERROR_CONF_TOPIC;
                goto err;
            }
            ret = reg_write(bar_addr, MIRP_BBASE_ADDR + offset, pMirp->cfgs[i].addr);
            if(ret != RET_SUCESS) {
                err_num = ret;
                goto err;
            }
            log_info("B UDP IP:0x%x,No:%d,Post=%d,ADDR=0x%x",
                     pMirp->cfgs[i].addr,
                     bnum,
                     bpost,
                     MIRP_BBASE_ADDR + offset);
            ret = reg_write(bar_addr, MIRP_BBASE_ADDR + offset + 4, pMirp->cfgs[i].port);
            if(ret != RET_SUCESS) {
                err_num = ret;
                goto err;
            }
            log_info("B UDP Port:%d,No:%d,Post=%d,ADDR=0x%x",
                     pMirp->cfgs[i].port,
                     bnum,
                     bpost,
                     MIRP_BBASE_ADDR + offset + 4);
            // log_info("B UDP IP:%x,Port:%d,No:%d,Post=%d,ADDR=%x",,,,,MIRP_BBASE_ADDR);
            // tsd_net_set_conf("B",pMirp->cfgs[i].addr,pMirp->cfgs[i].port,pMirp->cfgs[i].topic);
            bnum++;
        }
        if(pMirp->cfgs[i].porteEn_2) {

            if(cnum > COFIG_NODE_MAX) {
                err_num = ERROR_CONFIG_MIRPC;
                goto err;
            }
            if(pMirp->cfgs[i].topic == 5101) {
                cpost = 0;
                if(flag & 0x1000) {
                    offset = cpost * 16 + 8;
                    flag |= 0x2000;
                } else {
                    offset = cpost * 16;
                    flag |= 0x1000;
                }
            } else if(pMirp->cfgs[i].topic == 1101) {
                cpost = 1;
                if(flag & 0x4000) {
                    offset = cpost * 16 + 8;
                    flag |= 0x8000;
                } else {
                    offset = cpost * 16;
                    flag |= 0x4000;
                }
            } else {
                err_num = ERROR_CONF_TOPIC;
                goto err;
            }
            ret = reg_write(bar_addr, MIRP_CBASE_ADDR + offset, pMirp->cfgs[i].addr);
            if(ret != RET_SUCESS) {
                err_num = ret;
                goto err;
            }
            log_info("C UDP IP:0x%x,No:%d,Post=%d,ADDR=0x%x",
                     pMirp->cfgs[i].addr,
                     cnum,
                     cpost,
                     MIRP_CBASE_ADDR + offset);
            ret = reg_write(bar_addr, MIRP_CBASE_ADDR + offset + 4, pMirp->cfgs[i].port);
            if(ret != RET_SUCESS) {
                err_num = ret;
                goto err;
            }
            log_info("C UDP PORT:0x%x,No:%d,Post=%d,ADDR=0x%x",
                     pMirp->cfgs[i].port,
                     cnum,
                     cpost,
                     MIRP_CBASE_ADDR + offset + 4);
            // tsd_net_set_conf("C",pMirp->cfgs[i].addr,pMirp->cfgs[i].port,pMirp->cfgs[i].topic);
            cnum++;
        }
        if(pMirp->cfgs[i].porteEn_3) {
            if(dnum > COFIG_NODE_MAX) {
                err_num = ERROR_CONFIG_MIRPD;
                goto err;
            }
            if(pMirp->cfgs[i].topic == 5101) {
                dpost = 0;
                if(flag & 0x10000) {
                    offset = dpost * 16 + 8;
                    flag |= 0x20000;
                } else {
                    offset = dpost * 16;
                    flag |= 0x10000;
                }
            } else if(pMirp->cfgs[i].topic == 1101) {
                dpost = 1;
                if(flag & 0x40000) {
                    offset = dpost * 16 + 8;
                    flag |= 0x80000;
                } else {
                    offset = dpost * 16;
                    flag |= 0x40000;
                }
            } else {
                err_num = ERROR_CONF_TOPIC;
                goto err;
            }
            ret = reg_write(bar_addr, MIRP_DBASE_ADDR + offset, pMirp->cfgs[i].addr);
            if(ret != RET_SUCESS) {
                err_num = ret;
                goto err;
            }
            log_info("D UDP IP:0x%x,No:%d,Post=%d,ADDR=0x%x",
                     pMirp->cfgs[i].addr,
                     dnum,
                     dpost,
                     MIRP_DBASE_ADDR + offset);
            ret = reg_write(bar_addr, MIRP_DBASE_ADDR + offset + 4, pMirp->cfgs[i].port);
            if(ret != RET_SUCESS) {
                err_num = ret;
                goto err;
            }
            log_info("D UDP PORT:0x%x,No:%d,Post=%d,ADDR=0x%x",
                     pMirp->cfgs[i].port,
                     dnum,
                     dpost,
                     MIRP_DBASE_ADDR + offset + 4);
            // tsd_net_set_conf("D",pMirp->cfgs[i].addr,pMirp->cfgs[i].port,pMirp->cfgs[i].topic);
            dnum++;
        }
    }
err:
    return err_num;
}

int
id_tarInt(char* id) {
    int len;
    int i;
    unsigned short id_flag = 0;
    unsigned short id_num = 0;
    unsigned idnum_count = 0;
    unsigned idflag_count = 0;

    if((len = strlen(id)) > 6) return -1;
    for(i = 0; i < len; i++) {
        if(id[i] >= 0x30 && id[i] <= 0x39) {
            idnum_count++;
            if(idnum_count > 4) return -1;
            id_num |= (id[i] - '0') << (4 * (4 - idnum_count));
        } else {

            idflag_count++;
            if(idflag_count > 2) return -1;
            id_flag |= id[i] << (8 * (2 - idflag_count));
        }
    }
    return ((id_flag << 16) | id_num);
}

#define MODE_BIT_MASK       0xFFFFF100
#define MODE_QH_FILTER_MASK 0x1

int32_t
config_work_mode(unsigned char* bar_addr, int mod) {
    int ret = 0;
    int err_num = RET_SUCESS;
    if(mod & MODE_BIT_MASK) return ERROR_CONFIG_ARGS;
    if(mod & MODE_QH_FILTER_MASK) {
        if((mod & 0x3) != 0x3) return ERROR_CONFIG_ARGS;
    }
    write_le32(bar_addr, CONF_BOARD_MODEAB_REG, mod);
    log_info("ADDR:%x--AB Mode:%x", CONF_BOARD_MODEAB_REG, mod);
    return err_num;
}

int32_t
config_instruments(unsigned char* bar_addr, char** ppInstruments, int nCount) {
    int i;
    int ret = 0;
    int err_num = RET_SUCESS;
    clear_bar_map(bar_addr, INSTRUMENT_AB_FILTER_ADDR, 64);
    if(nCount == 0) goto err;
    if(NULL == ppInstruments) {
        err_num = ERROR_CONFIG_ARGS;
        goto err;
    }

    if(nCount > INSTRUMENTNO_COUNT) {
        err_num = ERROR_CONFIG_ARGS;
        goto err;
    }
    for(i = 0; i < nCount; i++) {
        // printf("%s\n",ppInstruments[i]);
        ret = id_tarInt(ppInstruments[i]);
        if(ret < 0) {
            err_num = ERROR_INSTRUMENT_STYLE;
            goto err;
        }
        write_le32(bar_addr, INSTRUMENT_AB_FILTER_ADDR + i * 4, ret);
        free(ppInstruments[i]);
        log_info("Filler ID %d:%s:%x", i, ppInstruments[i], ret);
    }
err:
    return err_num;
}

char*
map_fpga_dma_shared(void) {
    int fd;
    char* c2h_addr;
    unsigned int map_len = 0;
    fd = open(HUGE_PAGE_C2H_NODE, O_RDWR);
    if(fd < 0) return NULL;
    //  map_len = align_pagesize(QH_MAP_MEM_LEN);
    c2h_addr = (char*)mmap(0, HUG_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(c2h_addr == MAP_FAILED) {
        close(fd);
        return NULL;
    }
    close(fd);
    return c2h_addr;
}

void
map_release_dma_shared(char* ptr) {
    if(ptr) {
        munmap(ptr, HUG_PAGE_SIZE);
        ptr = NULL;
    }
}
#define TOPIC_1000_UDP_POST 0
#define TOPIC_5000_UDP_POST 1
#define TOPIC_2000_UDP_POST 2

void
read_fpga_state(int32_t* state, monitor_union* monitor, char* msg, int32_t msgSize) {
    int err_num = RET_SUCESS;
    int fd;
    unsigned char* bar0_addr;
    fd = open(DEVICE_BAR0_USR, O_RDWR);
    if(fd < 0) {
        err_num = ERROR_OPEN_USER;
        *state = err_num;
        return;
    }
    bar0_addr = (unsigned char*)mmap(NULL, MAP_BAR0_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(bar0_addr == (unsigned char*)MAP_FAILED) {
        close(fd);
        err_num = ERROR_MAP_USER;
        *state = err_num;
        return;
    }
    monitor->Version = *(volatile unsigned int*)(bar0_addr + VERSION_REG);
    monitor->ComplieTime = *(volatile unsigned int*)(bar0_addr + COMPILE_REG);

    monitor->IP_AUDP_QH[0] = *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR);
    monitor->IP_AUDP_QH[1] = *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + 8);
    monitor->Port_A_QH[0] = *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + 4);
    monitor->Port_A_QH[1] = *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + 12);

    monitor->IP_AUDP_INE[0] =
        *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + TOPIC_5000_UDP_POST * 16);
    monitor->IP_AUDP_INE[1] =
        *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + TOPIC_5000_UDP_POST * 16 + 8);
    monitor->Port_A_INE[0] =
        *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + TOPIC_5000_UDP_POST * 16 + 4);
    monitor->Port_A_INE[1] =
        *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + TOPIC_5000_UDP_POST * 16 + 12);

    monitor->IP_AUDP_METAL[0] =
        *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + TOPIC_2000_UDP_POST * 16);
    monitor->IP_AUDP_METAL[1] =
        *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + TOPIC_2000_UDP_POST * 16 + 8);
    monitor->Port_A_METAL[0] =
        *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + TOPIC_2000_UDP_POST * 16 + 4);
    monitor->Port_A_METAL[1] =
        *(volatile unsigned int*)(bar0_addr + MIRP_ABASE_ADDR + TOPIC_2000_UDP_POST * 16 + 12);

    monitor->IP_BUDP_QH[0] = *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR);
    monitor->IP_BUDP_QH[1] = *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + 8);
    monitor->Port_B_QH[0] = *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + 4);
    monitor->Port_B_QH[1] = *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + 12);

    monitor->IP_BUDP_INE[0] =
        *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + TOPIC_5000_UDP_POST * 16);
    monitor->IP_BUDP_INE[1] =
        *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + TOPIC_5000_UDP_POST * 16 + 8);
    monitor->Port_B_INE[0] =
        *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + TOPIC_5000_UDP_POST * 16 + 4);
    monitor->Port_B_INE[1] =
        *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + TOPIC_5000_UDP_POST * 16 + 12);

    monitor->IP_BUDP_METAL[0] =
        *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + TOPIC_2000_UDP_POST * 16);
    monitor->IP_BUDP_METAL[1] =
        *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + TOPIC_2000_UDP_POST * 16 + 8);
    monitor->Port_B_METAL[0] =
        *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + TOPIC_2000_UDP_POST * 16 + 4);
    monitor->Port_B_METAL[1] =
        *(volatile unsigned int*)(bar0_addr + MIRP_BBASE_ADDR + TOPIC_2000_UDP_POST * 16 + 12);

    monitor->IP_CUDP[0] = *(volatile unsigned int*)(bar0_addr + MIRP_CBASE_ADDR);
    monitor->IP_CUDP[1] = *(volatile unsigned int*)(bar0_addr + MIRP_CBASE_ADDR + 8);
    monitor->IP_CUDP[2] = *(volatile unsigned int*)(bar0_addr + MIRP_CBASE_ADDR + 16);
    monitor->IP_CUDP[3] = *(volatile unsigned int*)(bar0_addr + MIRP_CBASE_ADDR + 24);

    monitor->Port_C[0] = *(volatile unsigned int*)(bar0_addr + MIRP_CBASE_ADDR + 4);
    monitor->Port_C[1] = *(volatile unsigned int*)(bar0_addr + MIRP_CBASE_ADDR + 12);
    monitor->Port_C[2] = *(volatile unsigned int*)(bar0_addr + MIRP_CBASE_ADDR + 20);
    monitor->Port_C[3] = *(volatile unsigned int*)(bar0_addr + MIRP_CBASE_ADDR + 28);

    monitor->IP_DUDP[0] = *(volatile unsigned int*)(bar0_addr + MIRP_DBASE_ADDR);
    monitor->IP_DUDP[1] = *(volatile unsigned int*)(bar0_addr + MIRP_DBASE_ADDR + 8);
    monitor->IP_DUDP[2] = *(volatile unsigned int*)(bar0_addr + MIRP_DBASE_ADDR + 16);
    monitor->IP_DUDP[3] = *(volatile unsigned int*)(bar0_addr + MIRP_DBASE_ADDR + 24);

    monitor->Port_D[0] = *(volatile unsigned int*)(bar0_addr + MIRP_DBASE_ADDR + 4);
    monitor->Port_D[1] = *(volatile unsigned int*)(bar0_addr + MIRP_DBASE_ADDR + 12);
    monitor->Port_D[2] = *(volatile unsigned int*)(bar0_addr + MIRP_DBASE_ADDR + 20);
    monitor->Port_D[3] = *(volatile unsigned int*)(bar0_addr + MIRP_DBASE_ADDR + 28);

    monitor->TotalTCPPkt[0] = *(volatile unsigned int*)(bar0_addr + FPGA_ABTCP_PKTCOUNT_REG);
    monitor->TotalTCPPkt[1] = *(volatile unsigned int*)(bar0_addr + FPGA_CDTCP_PKTCOUNT_REG);

    monitor->TotalUDPPkt[0] = *(volatile unsigned int*)(bar0_addr + FPGA_AUDP_VALID_REG);
    monitor->TotalUDPPkt[1] = *(volatile unsigned int*)(bar0_addr + FPGA_BUDP_VALID_REG);
    monitor->TotalUDPPkt[2] = *(volatile unsigned int*)(bar0_addr + FPGA_CUDP_VALID_REG);
    monitor->TotalUDPPkt[3] = *(volatile unsigned int*)(bar0_addr + FPGA_DUDP_VALID_REG);

    monitor->SHFEUDPPkt[0] = *(volatile unsigned int*)(bar0_addr + SH2PS_1000_UDP_AREG);
    monitor->SHFEUDPPkt[1] = *(volatile unsigned int*)(bar0_addr + SH2PS_1000_UDP_BREG);
    monitor->SHFEUDPPkt[2] = *(volatile unsigned int*)(bar0_addr + SH2PS_1000_UDP_CREG);
    monitor->SHFEUDPPkt[3] = *(volatile unsigned int*)(bar0_addr + SH2PS_1000_UDP_DREG);
    monitor->SHFEUDPPkt[4] = *(volatile unsigned int*)(bar0_addr + SH2PS_2000_UDP_AREG);
    monitor->SHFEUDPPkt[5] = *(volatile unsigned int*)(bar0_addr + SH2PS_2000_UDP_BREG);
    monitor->SHFEUDPPkt[6] = *(volatile unsigned int*)(bar0_addr + SH2PS_2000_UDP_CREG);
    monitor->SHFEUDPPkt[7] = *(volatile unsigned int*)(bar0_addr + SH2PS_2000_UDP_DREG);

    monitor->INEUDPPkt[0] = *(volatile unsigned int*)(bar0_addr + INE_UDP_AREG);
    monitor->INEUDPPkt[1] = *(volatile unsigned int*)(bar0_addr + INE_UDP_BREG);
    monitor->INEUDPPkt[2] = *(volatile unsigned int*)(bar0_addr + INE_UDP_CREG);
    monitor->INEUDPPkt[3] = *(volatile unsigned int*)(bar0_addr + INE_UDP_DREG);

    monitor->DMAUpload = *(volatile unsigned int*)(bar0_addr + DMA_UPLOAD_COUNT_REG);
    unsigned int ExceptionEvent_value = 0;
#define NET_STU_MASK 0x1F
    ExceptionEvent_value |=
        (*(volatile unsigned int*)(bar0_addr + NET_LINK_STU_REG)) & NET_STU_MASK;
    unsigned int crc_flag = 0;
    unsigned int value = 0;
    value = *(volatile unsigned int*)(bar0_addr + AERR_CRC_PKT);
    if(value) crc_flag |= 1;
    value = *(volatile unsigned int*)(bar0_addr + BERR_CRC_PKT);
    if(value) crc_flag |= 1 << 1;
    value = *(volatile unsigned int*)(bar0_addr + CERR_CRC_PKT);
    if(value) crc_flag |= 1 << 2;
    value = *(volatile unsigned int*)(bar0_addr + DERR_CRC_PKT);
    if(value) crc_flag |= 1 << 3;
    ExceptionEvent_value |= crc_flag << 5;
#define CENTER_CHANGE_ADDR_REG 0x212
#define CENTER_AB_MASK         0xffff
#define CENTER_CD_MASK         0xffff0000
    unsigned int center_change_flag = 0;
    value = *(volatile unsigned int*)(bar0_addr + CENTER_CHANGE_ADDR_REG);
    if(value) {
        if(value & CENTER_AB_MASK) center_change_flag |= 0x1;
        if(value & CENTER_CD_MASK) center_change_flag |= 0x2;
    }
    value = *(volatile unsigned int*)(bar0_addr + CENTER_CHANGE_ADDR_REG + 4);
    if(value) {
        if(value & CENTER_AB_MASK) center_change_flag |= 0x1;
        if(value & CENTER_CD_MASK) center_change_flag |= 0x2;
    }
    value = *(volatile unsigned int*)(bar0_addr + CENTER_CHANGE_ADDR_REG + 8);
    if(value) {
        if(value & CENTER_AB_MASK) center_change_flag |= 0x1;
        if(value & CENTER_CD_MASK) center_change_flag |= 0x2;
    }
    if(center_change_flag) ExceptionEvent_value |= center_change_flag << 9;
    monitor->ExceptionEvent = ExceptionEvent_value;
    munmap(bar0_addr, MAP_BAR0_LEN);
    close(fd);
    *state = err_num;
}

#define page_map_file    "/proc/self/pagemap"
#define PFN_MASK         ((((unsigned long)1) << 55) - 1)
#define PFN_PRESENT_FLAG (((unsigned long)1) << 63)

int
mem_addr_vir2phy(unsigned long vir, unsigned long* phy) {
    int fd;
    int page_size = getpagesize();
    unsigned long vir_page_idx = vir / page_size;
    unsigned long pfn_item_offset = vir_page_idx * sizeof(unsigned long);
    unsigned long pfn_item;
    fd = open(page_map_file, O_RDONLY);
    if(fd < 0) {
        fprintf(stderr, "open %s failed", page_map_file);
        return -1;
    }
    if((off_t)-1 == lseek(fd, pfn_item_offset, SEEK_SET)) {
        fprintf(stderr, "lseek %s failed", page_map_file);
        return -1;
    }
    if(sizeof(unsigned long) != read(fd, &pfn_item, sizeof(unsigned long))) {
        fprintf(stderr, "read %s failed", page_map_file);
        return -1;
    }
    if(0 == (pfn_item & PFN_PRESENT_FLAG)) {
        fprintf(stderr, "page is not present");
        return -1;
    }
    *phy = (pfn_item & PFN_MASK) * page_size + vir % page_size;
    return 0;
}

typedef struct __instruments_filter {
    char* Instruments[64];
    unsigned int count;
} cfg_instruments_filter;

typedef struct __iniinf {
    cfg_mirp Mirp;
    cfg_mdqp Mdqp;
    unsigned int topic_id[10];
    unsigned int topic_count;
    cfg_instruments_filter filter;
    unsigned int ab_work_mode;
} iniinf;

int
strotl_get_str(const char* in, int* out, int* count) {
    char* p;
    unsigned int num = 0;
    p = strtok((char*)in, ",");
    if(NULL == p) {
        *count = num;
        return num;
    }
    *(out + num) = atoi(p);
    num++;
    do {
        p = strtok(NULL, ",");
        if(NULL == p) {
            *count = num;
            break;
        }
        *(out + num) = atoi(p);
        num++;
    } while(1);
    return num;
}

int
strotl_get_ip_port(const char* in, unsigned int* ip, unsigned int* port) {
    char* p;
    // unsigned int data = 0;
    p = strtok((char*)in, ":");
    if(NULL == p) return -1;
    *ip = (unsigned int)ntohl(inet_addr(p));
    do {
        p = strtok(NULL, ":");
        if(NULL == p) break;
        *port = atoi(p);
        //  data = *port;
    } while(1);
    if(port == 0) return -1;
    return 0;
}

#define AB_PORT_ENABLE 0x3
int
ini_parse_get(char* file, iniinf* conf) {
    dictionary* ini;
    int ret;
    int count = 0;
    int topic[10] = { 0 };
    const char* pstr;
    unsigned int tmp = 0;
    int i = 0, j = 0;
    unsigned int ip = 0, port = 0;
    int err_num = RET_SUCESS;
    // unsigned int tcp_count = 0;
    ini = iniparser_load(file);
    if(ini == NULL) return ERROR_INICONF_LOAD;
    pstr = iniparser_getstring(ini, "cfg:sh2ps", NULL);
    if(pstr != NULL) {
        strotl_get_str(pstr, topic, &ret);
        count += ret;
    }
    pstr = iniparser_getstring(ini, "cfg:ine2ps", NULL);
    if(pstr != NULL) {
        strotl_get_str(pstr, topic + count, &ret);
        count += ret;
    }
    pstr = iniparser_getstring(ini, "cfg:sh4ps", NULL);
    if(pstr != NULL) {
        strotl_get_str(pstr, topic + count, &ret);
        count += ret;
    }

    pstr = iniparser_getstring(ini, "cfg:ine4ps", NULL);
    if(pstr != NULL) {
        strotl_get_str(pstr, topic + count, &ret);
        count += ret;
    }
    if(count == 0) {
        err_num = ERROR_INICONF_INFO;
        goto err;
    }
    for(i = 0; i < count; i++) conf->topic_id[i] = topic[i];
    conf->topic_count = count;
#define DA_FLAG_MASK    0x3
#define ZJ_FLAG_MASK    0xc
#define ZJ4PS_FLAG_MASK 0xF0
    char ini_key[128] = { 0 };
    const char bit_name[8][50] = { "a1", "a2", "b1", "b2", "c1", "c2", "c3", "c4" };
    int tcp_flag = 0;
    for(i = 0; i < 8; i++) {
        memset(ini_key, 0, sizeof(ini_key));
        sprintf(ini_key, "tcp:tcp_ip_%s", bit_name[i]);
        pstr = iniparser_getstring(ini, ini_key, NULL);
        if(pstr) {
            if(strotl_get_ip_port(pstr, &ip, &port) < 0) {
                err_num = ERROR_INICONF_TCP;
                goto err;
            }
            tmp = conf->Mdqp.cfg_num;
            conf->Mdqp.cfgs[tmp].addr = ip;
            conf->Mdqp.cfgs[tmp].port = port;
            if(strncmp(bit_name[i], "c", 1) == 0) {
                conf->Mdqp.cfgs[tmp].porteEn_2 = 1;
                tcp_flag |= ZJ4PS_FLAG_MASK;
            } else {
                conf->Mdqp.cfgs[tmp].porteEn_0 = 1;
                if(strncmp(bit_name[i], "a", 1) == 0) tcp_flag |= DA_FLAG_MASK;
                else if(strncmp(bit_name[i], "b", 1) == 0) tcp_flag |= ZJ_FLAG_MASK;
            }
            conf->Mdqp.cfg_num++;
            tcp_flag |= 1 << i;
        }
    }
    if(conf->Mdqp.cfg_num == 0) {
        err_num = ERROR_INICONF_TCP;
        goto err;
    }

    const char udp_name[8][20] = { "aa", "ab", "ba", "bb", "cc", "cd", "dc", "dd" };
    unsigned int topic_flag = 0;
    for(i = 0; i < count; i++) {
        topic_flag = 0;
        for(j = 0; j < 8; j++) {
            if(udp_name[j][0] == 'a') {
                if(!(tcp_flag & DA_FLAG_MASK)) continue;
            } else if(udp_name[j][0] == 'b') {
                if(!(tcp_flag & ZJ_FLAG_MASK)) continue;
            } else if(udp_name[j][0] == 'c') {
                if(!(tcp_flag & ZJ4PS_FLAG_MASK)) continue;
            } else if(udp_name[j][0] == 'd') {
                if(!(tcp_flag & ZJ4PS_FLAG_MASK)) continue;
            } else {
                continue;
            }
            memset(ini_key, 0, sizeof(ini_key));
            sprintf(ini_key, "%d:udp_ip_%s", topic[i], udp_name[j]);
            pstr = iniparser_getstring(ini, ini_key, NULL);
            if(pstr) {
                if(strotl_get_ip_port(pstr, &ip, &port) < 0) {
                    err_num = ERROR_INICONF_UDP;
                    goto err;
                }
                tmp = conf->Mirp.cfg_num;
                if(udp_name[j][1] == 'a') conf->Mirp.cfgs[tmp].porteEn_0 = 1;
                else if(udp_name[j][1] == 'b') conf->Mirp.cfgs[tmp].porteEn_1 = 1;
                else if(udp_name[j][1] == 'c') conf->Mirp.cfgs[tmp].porteEn_2 = 1;
                else if(udp_name[j][1] == 'd') conf->Mirp.cfgs[tmp].porteEn_3 = 1;
                conf->Mirp.cfgs[tmp].addr = ip;
                conf->Mirp.cfgs[tmp].port = port;
                conf->Mirp.cfgs[tmp].topic = topic[i];
                conf->Mirp.cfg_num++;
                topic_flag = 1;
            } else {
                // err_num = ERROR_INICONF_TOPIC;
                // goto err;
                continue;
            }
        }
        if(!topic_flag) {
            err_num = ERROR_INICONF_UDP;
            goto err;
        }
    }
    ret = iniparser_getint(ini, "upload_mode:filter_en", -1);
    if(ret == -1) {
        err_num = ERROR_INICONF_FILTER_EN;
        goto err;
    }
    if(ret == 1) {
        pstr = iniparser_getstring(ini, "upload_mode:filter_file", NULL);
        if(NULL == pstr) {
            err_num = ERROR_INICONF_FILTER_FILE;
            goto err;
        }
        if(access(pstr, F_OK)) {
            err_num = ERROR_INICONF_FILTER_FILE;
            goto err;
        }
        FILE* pfd;
        char* pdata;
        char rxbuf[512] = { 0 };
        pfd = fopen(pstr, "r");
        if(NULL == pfd) {
            err_num = ERROR_INICONF_FILTER_FILE;
            goto err;
        }
        for(;;) {
            if(conf->filter.count > 64) {
                fclose(pfd);
                err_num = ERROR_INICONF_FILTER_CROSS;
                goto err;
            }
            memset(rxbuf, 0, sizeof(rxbuf));
            pdata = fgets(rxbuf, sizeof(rxbuf), pfd);
            if(NULL == pdata) break;
            for(i = 0; i < strlen(rxbuf); i++) {
                if(rxbuf[i] >= 0x30 && rxbuf[i] <= 0x39) continue;
                if(rxbuf[i] >= 0x41 && rxbuf[i] <= 0x5A) continue;
                if(rxbuf[i] >= 0x61 && rxbuf[i] <= 0x7A) continue;
                rxbuf[i] = '\0';
            }
            char* p = calloc(0, 64);
            if(NULL == p) {
                err_num = ERROR_CALLOC;
                goto err;
            }
            strcpy(p, rxbuf);
            conf->filter.Instruments[conf->filter.count] = p;
            conf->filter.count++;
        }
        fclose(pfd);
        if(0 == conf->filter.count) {
            err_num = ERROR_INICONF_FILTER_FILE;
            goto err;
        }
        conf->ab_work_mode |= 0x1;
    }
    ret = iniparser_getint(ini, "upload_mode:class1_en", -1);
    if(ret == 1) conf->ab_work_mode |= 0x2;

    ret = iniparser_getint(ini, "upload_mode:class2_en", -1);
    if(ret == 1) conf->ab_work_mode |= 0x4;

    ret = iniparser_getint(ini, "upload_mode:class3_en", -1);
    if(ret == 1) conf->ab_work_mode |= 0x8;

    ret = iniparser_getint(ini, "upload_mode:class4_en", -1);
    if(ret == 1) conf->ab_work_mode |= 0x10;

    ret = iniparser_getint(ini, "upload_mode:class5_en", -1);
    if(ret == 1) conf->ab_work_mode |= 0x20;

    ret = iniparser_getint(ini, "upload_mode:class6_en", -1);
    if(ret == 1) conf->ab_work_mode |= 0x40;

    ret = iniparser_getint(ini, "upload_mode:class7_en", -1);
    if(ret == 1) conf->ab_work_mode |= 0x80;

err:
    iniparser_freedict(ini);
    return err_num;
}
#if 1
int
ini_conf_test(char* conf_file) {
    int ret;
    iniinf conf = { 0 };
    int i;
    int count;
    if((ret = ini_parse_get(conf_file, &conf)) == RET_SUCESS) {
        count = conf.Mdqp.cfg_num;
        for(i = 0; i < count; i++) {
            printf("addr=%x\n", conf.Mdqp.cfgs[i].addr);
            printf("port=%d\n", conf.Mdqp.cfgs[i].port);
        }

        count = conf.Mirp.cfg_num;
        for(i = 0; i < count; i++) {
            printf("addr=%x\n", conf.Mirp.cfgs[i].addr);
            printf("port=%d\n", conf.Mirp.cfgs[i].port);
            printf("topic=%d\n", conf.Mirp.cfgs[i].topic);
        }
        printf("mod=%x\n", conf.ab_work_mode);
        count = conf.filter.count;
        for(i = 0; i < count; i++) printf("%s\n", conf.filter.Instruments[i]);
    }
    return ret;
}
#endif

int
init_fpga(void* param) {
    DIR* dir = NULL;
    char sys_cmd[512] = { 0 };
    pthread_t pid;
    int fd;
    int pfd;
    int err_num = RET_SUCESS;
    unsigned char* c2h_addr;
    unsigned long c2h_phy_addr;
    unsigned char* bar0_addr;
    unsigned char* bar1_addr;
    int ret;
    unsigned int flag = 0;
    iniinf conf = { 0 };

    memset(&conf, 0, sizeof(conf));
    if((ret = ini_parse_get(param, &conf)) != RET_SUCESS) return ret;
    fd = open(HUGE_PAGE_C2H_NODE, O_CREAT | O_RDWR, 600);
    if(fd < 0) return ERROR_OPEN_PAGE;
    c2h_addr = (unsigned char*)mmap(0, HUG_PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(c2h_addr == MAP_FAILED) {
        close(fd);
        return ERROR_MAP_PAGE;
    }
    memset(c2h_addr, 0, HUG_PAGE_SIZE);
    mem_addr_vir2phy((unsigned long)c2h_addr, &c2h_phy_addr);
    munmap(c2h_addr, HUG_PAGE_SIZE);
    close(fd);

    fd = open(DEVICE_BAR0_USR, O_RDWR);
    if(fd < 0) return ERROR_OPEN_USER;
    bar0_addr = (unsigned char*)mmap(NULL, MAP_BAR0_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(bar0_addr == (unsigned char*)MAP_FAILED) {
        close(fd);
        return ERROR_MAP_USER;
    }

    write_le32(bar0_addr, FPGA_RESET_REG, 1);
    log_info("FPGA_RESET_REG ADDR=%x--VALUE:%d", FPGA_RESET_REG, 1);
    usleep(10);
    write_le32(bar0_addr, FPGA_RESET_REG, 0);
    log_info("FPGA_RESET_REG ADDR=%x--VALUE:%d", FPGA_RESET_REG, 0);
    // tsd_conf_file_unlink();
    if(*(unsigned int*)(bar0_addr + PCIE_DMA_DST_ADDR_H) != (c2h_phy_addr >> 32)) {
        write_le32(bar0_addr, PCIE_DMA_DST_ADDR_H, c2h_phy_addr >> 32);
        log_info("PCIE_DMA_DST_ADDR_H ADDR0x=%x--VALUE0x:%x",
                 PCIE_DMA_DST_ADDR_H,
                 c2h_phy_addr >> 32);
    }
    if(*(unsigned int*)(bar0_addr + PCIE_DMA_DST_ADDR_L) != (c2h_phy_addr & 0xFFFFFFFF)) {
        write_le32(bar0_addr, PCIE_DMA_DST_ADDR_L, c2h_phy_addr);
        log_info("PCIE_DMA_DST_ADDR_L ADDR0x=%x--VALUE0x:%x", PCIE_DMA_DST_ADDR_L, c2h_phy_addr);
    }
    munmap(bar0_addr, MAP_BAR0_LEN);
    close(fd);
#if 0
	fd=open(DEVICE_BAR1_CNTRL,O_RDWR);
	if(fd < 0)
		return ERROR_OPEN_USER;
	bar1_addr = (unsigned char *)mmap(NULL,MAP_BAR1_LEN,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
	if (bar1_addr == (unsigned char *)MAP_FAILED) {
			close(fd);
			return ERROR_MAP_BAR1;
	}
	if(*(unsigned int *)(bar1_addr+MAP_BAR1_TXENABLE) != 4){
		write_le32(bar1_addr,MAP_BAR1_TXENABLE,4);
	}
	if(*(unsigned int *)(bar1_addr+MAP_BAR1_ENABLE) != 1){
		write_le32(bar1_addr,MAP_BAR1_ENABLE,1);
	}
	munmap(bar1_addr,MAP_BAR1_LEN);
	close(fd);
#endif
    fd = open(DEVICE_BAR0_USR, O_RDWR);
    if(fd < 0) return ERROR_OPEN_USER;
    bar0_addr = (unsigned char*)mmap(NULL, MAP_BAR0_LEN, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if(bar0_addr == (unsigned char*)MAP_FAILED) {
        close(fd);
        return ERROR_MAP_USER;
    }

    if((err_num = config_instruments(bar0_addr, conf.filter.Instruments, conf.filter.count)) !=
       RET_SUCESS) {
        goto err;
    }
    if((err_num = config_topic(bar0_addr, conf.topic_id, conf.topic_count)) != RET_SUCESS) goto err;
    if((err_num = config_work_mode(bar0_addr, conf.ab_work_mode)) != RET_SUCESS) goto err;

    if((err_num = config_udp(bar0_addr, &conf.Mirp)) != RET_SUCESS) goto err;

    if((err_num = config_tcp(bar0_addr, &conf.Mdqp)) != RET_SUCESS) goto err;

    write_le32(bar0_addr, 0x1C, 1);
    log_info("ADDR 0x1c value 1");
    write_le32(bar0_addr, 0x1C, 0);
    log_info("ADDR 0x1c value 0");
err:
    munmap(bar0_addr, MAP_BAR0_LEN);
    close(fd);
    return err_num;
}
