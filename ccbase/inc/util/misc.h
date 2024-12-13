#ifndef MISC_H__
#define MISC_H__

#include <float.h>
#include <time.h>

#if defined(__cplusplus) && (__cplusplus > 0)
extern "C"
{
#endif

#define PRINT_HEX(field, name) \
    printf("%s: 0x%02x\n", #name, field.name);

#define PRINT_HEX_4(field, name) \
    printf("%s: 0x%04x\n", #name, field.name);

#define PRINT_HEX_8(field, name) \
    printf("%s: 0x%08x\n", #name, field.name);

#define PRINT_INT(field, name) \
    printf("%s: %d \n", #name, field.name);

#define PRINT_VINT(field, name) \
    printf("%s: %ld\n", #name, field.name);

#define PRINT_STR(field, name) \
    printf("%s: \"%s\"\n", #name, field.name);

#define PRINT_CHAR(field, name) \
    printf("%s: '%c'\n", #name, field.name);

#define PRINT_DOUBLE(field, name)       \
    if (field.name >= DBL_MAX)          \
        printf("%s: DBL_MAX\n", #name); \
    else                                \
        printf("%s: %0.2f\n", #name, field.name);

#define PRINT_HEX_CSV(field, name) \
    printf("0x%02x,", field.name);

#define PRINT_HEX_4_CSV(field, name) \
    printf("0x%04x,", field.name);

#define PRINT_HEX_8_CSV(field, name) \
    printf("0x%08x,", field.name);

#define PRINT_INT_CSV(field, name) \
    printf("%d,", field.name);

#define PRINT_VINT_CSV(field, name) \
    printf("%ld,", field.name);

#define PRINT_STR_CSV(field, name) \
    printf("%s,", field.name);

#define PRINT_CHAR_CSV(field, name) \
    printf("%c,", field.name);

#define PRINT_DOUBLE_CSV(field, name) \
    if (field.name >= DBL_MAX)        \
        printf("DBL_MAX,");           \
    else                              \
    {                                 \
        field.name += 0.00005;        \
        printf("%0.4f,", field.name); \
    }

    void print_bin(unsigned char value);
    void print_hex(unsigned char *buffer, int size);
    unsigned char fun(char c);
    int convert(const char *str, char *arr);
    void timestamp_date_str(time_t t, char *buf, int size);
    void timestamp_time_str(time_t t, char *buf, int size);
    void timestamp_day_str(time_t t, char *buf, int size);

    typedef struct ndate
    {
        int year;
        int month;
        int day;
    } ndate_t;

    ndate_t today();
    ndate_t calculate_date(ndate_t *initDate, int diffDays);

    double get_timestamp();

#if defined(__cplusplus) && (__cplusplus > 0)
}
#endif

#endif