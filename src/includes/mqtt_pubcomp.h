#include <stdint.h>

#define MQTT_PUBCOMP_FIXED_HEADER_LEN 2

#define MQTT_PKT_PUBCOMP_PUBLIC_MEMBER \
    struct \
    { \
        int (*get_pkt_id)(struct MQTT_PKT_PUBCOMP_S *mqtt_pkt_pubcomp); \
        int (*set_pkt_id)(struct MQTT_PKT_PUBCOMP_S *mqtt_pkt_pubcomp, int pkt_id); \
        int (*encode)(struct MQTT_PKT_PUBCOMP_S *mqtt_pkt_pubcomp, uint8_t *buf); \
    }

#define MQTT_PKT_PUBCOMP_PRIVATE_MEMBER \
    struct \
    { \
        unsigned int pkt_id; \
        \
        MQTT_PKT_FIXED_HEADER *mqtt_fixed_header; \
        MQTT_PKT_VAR_HEADER *mqtt_var_header; \
    }

typedef struct MQTT_PKT_PUBCOMP_S
{
    MQTT_PKT_PUBCOMP_PUBLIC_MEMBER;
}MQTT_PKT_PUBCOMP;

struct MQTT_PKT_PUBCOMP_S *mqtt_pkt_pubcomp_create();

int mqtt_pkt_pubcomp_init(struct MQTT_PKT_PUBCOMP_S *mqtt_pkt_pubcomp, unsigned int pkt_id);

struct MQTT_PKT_PUBCOMP_S  *mqtt_pkt_pubcomp_decode(uint8_t *buf, int len);

int destroy_pubcomp(struct MQTT_PKT_PUBCOMP_S *mqtt_pkt_pubcomp);

