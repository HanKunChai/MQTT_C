
#include <stdint.h>

#define MQTT_FIX_HEADER_LEN 2

/* fixed header struct*/
#define MQTT_PKT_FIXED_HEADER_PUBLIC_MEMBER \
    struct \
    { \
        int (*get_pkt_len)(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header); \
        uint8_t (*get_pkt_type)(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header); \
        uint8_t (*get_pkt_flag)(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header); \
        int (*get_pkt_rem_len)(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header); \
        int (*set_pkt_type)(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header, uint8_t type); \
        int (*set_pkt_flag)(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header, uint8_t flag); \
        int (*set_pkt_rem_len)(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header, int rem_len); \
        \
        int (*encode)(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header, uint8_t *buf); \
    }
    

#define MQTT_PKT_FIXED_HEADER_PRIVATE_MEMBER \
    struct \
    { \
        int pkt_len; \
        uint8_t pkt_type; \
        uint8_t pkt_flag; \
        int pkt_rem_len; \
    }

typedef struct MQTT_PKT_FIXED_HEADER_S
{
    MQTT_PKT_FIXED_HEADER_PUBLIC_MEMBER;
}MQTT_PKT_FIXED_HEADER;

struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header_decode(uint8_t *buf, int len);

extern MQTT_PKT_FIXED_HEADER *mqtt_fixed_header_create();
extern int destroy_fixed_header(MQTT_PKT_FIXED_HEADER *mqtt_fixed_header);

