#ifndef TSD_MD_API_H__
#define TSD_MD_API_H__

#include <stdint.h>

#define __cdecl

#if 1

typedef struct __monitor_union
{
	uint32_t Version;
	uint32_t ComplieTime;
	uint32_t IP_AUDP_QH[2];
	uint16_t Port_A_QH[2];
	uint32_t IP_AUDP_METAL[2];
	uint16_t Port_A_METAL[2];
	uint32_t IP_AUDP_INE[2];
	uint16_t Port_A_INE[2];
	uint32_t IP_BUDP_QH[2];
	uint16_t Port_B_QH[2];
	uint32_t IP_BUDP_METAL[2];
	uint16_t Port_B_METAL[2];
	uint32_t IP_BUDP_INE[2];
	uint16_t Port_B_INE[2];
	uint32_t IP_CUDP[4];
	uint32_t IP_DUDP[4];
	uint16_t Port_C[4];
	uint16_t Port_D[4];
	uint32_t TotalTCPPkt[2];
	uint32_t TotalUDPPkt[4];
	uint32_t SHFEUDPPkt[8];
	uint32_t INEUDPPkt[4];
	uint32_t DMAUpload;
	uint32_t ExceptionEvent;

} monitor_union;
#else

typedef struct __monitor_union
{
	uint32_t Version;
	uint32_t ComplieTime;
	uint32_t IP_AUDP[4];
	uint32_t IP_BUDP[4];
	uint16_t Port_A[4];
	uint16_t Port_B[4];
	uint32_t IP_CUDP[4];
	uint32_t IP_DUDP[4];
	uint16_t Port_C[4];
	uint16_t Port_D[4];
	uint32_t TotalTCPPkt[2];
	uint32_t TotalUDPPkt[4];
	uint32_t SHFEUDPPkt[8];
	uint32_t INEUDPPkt[4];
	uint32_t DMAUpload;
	uint32_t ExceptionEvent;
} monitor_union;

#endif
#ifdef __cplusplus 

    extern "C" { 

#endif





/**@brief  MAP FPGA DMA
 * @return the start of allocated memory for DMA write to host
 *         ringbuffer -- which contain the list of most recently updated insturment ids
 *         databuffer -- contains the updated marketing data
 */
char *map_fpga_dma_shared(void);
void map_release_dma_shared(char *ptr);

/**@brief  check FPGA status
 * @return state: the status of FPGA as an integer for example, 0 for ok, 1 for data error etc.
           msg: the description of the status
           msgSize: the maximum msg buffer

    TODO：  FPGA接受数据包出现异常，需要告知软件。未来可以考虑读取软件当前解码的快照
 */
void read_fpga_state(int32_t *state, monitor_union* monitor, char *msg, int32_t msgSize);

/**@brief  reset fpga data and dma data
 * @param  
 * @return 0 on success not 0 for failed
 */
int init_fpga(void * param);
int ini_conf_test(char *conf_file);


#ifdef __cplusplus 
 		}
#endif
#endif
