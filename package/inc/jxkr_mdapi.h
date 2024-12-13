#ifndef JXKR_MD_API_H__
#define JXKR_MD_API_H__

#include "instrument.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#ifdef WINDOWS
#define JXKR_MDAPI
#else
#define JXKR_MDAPI __attribute__((visibility("default")))
#endif

    typedef enum jxrk_md_status
    {
        JXKR_MD_OK = 0,
        JXKR_MD_NOT_AUTHORIZED,
        JXKR_MD_TICKET_EXPRIED,
        JXKR_MD_TICKET_INVALID,
        JXKR_MD_TICKET_NO_MAC_MATCHED,
        JXKR_MD_THREAD_ERROR,
        JXKR_MD_SHARED_MEMORY_ERROR,
        JXKR_MD_PARAM_ERROR,
        JXKR_MD_HUGE_ERROR,
        JXKR_MD_CONF_ERROR,
        JXKR_MD_FPGA_ERROR = 100
    } jxkr_md_status_t;

    typedef enum quote_mode
    {
        QM_MASTER,
        QM_SLAVE
    } quote_mode_t;

    /**
     * @brief init hq board
     *
     */
    JXKR_MDAPI jxkr_md_status_t jxkr_init_hq_board(char *confName, quote_mode_t mode);

    JXKR_MDAPI instrument_t *jxkr_next();
    JXKR_MDAPI jxkr_md_status_t jxkr_prepare();

    /**@brief  set the call back function
     * @param  cb:  the call back function to be set
     */
    JXKR_MDAPI jxkr_md_status_t jxkr_md_set_callback(void (*cb)(instrument_t *));

    /**@brief  set the call back function
     * @param  cb:  the call back function to be set
     */
    JXKR_MDAPI jxkr_md_status_t jxkr_md_set_callback(void (*cb)(instrument_t *));

    /**
     * @brief a loop thread to check for market data until isAlive is false
     *
     * @param cpuid  the cpu id to be bound to the thread
     * @param isAlive running flag, if 1 keep running, 0 stop running
     * @return JXKR_MD_OK on success, otherwise failed
     */
    JXKR_MDAPI jxkr_md_status_t jxkr_md_loop(int cpuid, int *isAlive);

    /**@brief block to wait for loop thread to end
     */
    JXKR_MDAPI jxkr_md_status_t jxkr_md_wait_for_loop();

    /**@brief get api version
     */
    JXKR_MDAPI const char *jxkr_md_api_version();

    /**@brief use the ticket to authorize API
     */
    JXKR_MDAPI jxkr_md_status_t jxkr_md_api_authorize(const char *ticket);

#if defined(__cplusplus)
}
#endif

#endif