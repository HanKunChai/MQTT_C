#include <stdint.h>

#define MQTT_FIX_HEADER_LEN 2

#define MQTT_PKT_PUBREL_PUBLIC_MEMBER \
    struct \
    { \
        int (*get_pkt_id)(struct MQTT_PKT_PUBREL_S *mqtt_pkt_pubrel); \
        int (*set_pkt_id)(struct MQTT_PKT_PUBREL_S *mqtt_pkt_pubrel, int pkt_id); \
        int (*encode)(struct MQTT_PKT_PUBREL_S *mqtt_pkt_pubrel, uint8_t *buf); \
    }

#define MQTT_PKT_PUBREL_PRIVATE_MEMBER \
    struct \
    { \
        unsigned int pkt_id; \
        \
        MQTT_PKT_FIXED_HEADER *mqtt_fixed_header; \
        MQTT_PKT_VAR_HEADER *mqtt_var_header; \
    }

typedef struct MQTT_PKT_PUBREL_S
{
    MQTT_PKT_PUBREL_PUBLIC_MEMBER;
}MQTT_PKT_PUBREL;

struct MQTT_PKT_PUBREL_S *mqtt_pkt_pubrel_create();

int mqtt_pkt_pubrel_init(struct MQTT_PKT_PUBREL_S *mqtt_pkt_pubrel, unsigned int pkt_id);

struct MQTT_PKT_PUBREL_S  *mqtt_pkt_pubrel_decode(uint8_t *buf, int len);

int destroy_pubrel(struct MQTT_PKT_PUBREL_S *mqtt_pkt_pubrel);

