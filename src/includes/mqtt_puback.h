#include <stdint.h>

#define MQTT_PUBACK_FIXED_HEADER_LEN 2

#define MQTT_PUBACK_PUBLIC_MEMBER \
    struct \
    { \
        int (*get_pkt_id)(struct MQTT_PKT_PUBACK_S *mqtt_pkt_puback); \
        int (*set_pkt_id)(struct MQTT_PKT_PUBACK_S *mqtt_pkt_puback, int pkt_id); \
        int (*encode)(struct MQTT_PKT_PUBACK_S *mqtt_pkt_puback, uint8_t *buf); \
    }

#define MQTT_PUBACK_PRIVATE_MEMBER \
    struct \
    { \
        uint16_t pkt_id; \
        \
        MQTT_PKT_FIXED_HEADER *mqtt_fixed_header; \
        MQTT_PKT_VAR_HEADER *mqtt_var_header; \
    }

typedef struct MQTT_PKT_PUBACK_S
{
    MQTT_PUBACK_PUBLIC_MEMBER;
}MQTT_PKT_PUBACK;

struct MQTT_PKT_PUBACK_S *mqtt_pkt_puback_create();

int mqtt_pkt_puback_init(struct MQTT_PKT_PUBACK_S *mqtt_pkt_puback, uint16_t pkt_id);

struct MQTT_PKT_PUBACK_S  *mqtt_pkt_puback_decode(uint8_t *buf, int len);

int destroy_puback(struct MQTT_PKT_PUBACK_S *mqtt_pkt_puback);

