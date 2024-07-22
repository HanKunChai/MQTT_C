#include <stdint.h>

#define MQTT_PUBREC_FIXED_HEADER_LEN 2

#define MQTT_PUBREC_PUBLIC_MEMBER \
    struct \
    { \
        int (*get_pkt_id)(struct MQTT_PKT_PUBREC_S *mqtt_pkt_pubrec); \
        int (*set_pkt_id)(struct MQTT_PKT_PUBREC_S *mqtt_pkt_pubrec, int pkt_id); \
        int (*encode)(struct MQTT_PKT_PUBREC_S *mqtt_pkt_pubrec, uint8_t *buf); \
    }

#define MQTT_PUBREC_PRIVATE_MEMBER \
    struct \
    { \
        unsigned int pkt_id; \
        \
        MQTT_PKT_FIXED_HEADER *mqtt_fixed_header; \
        MQTT_PKT_VAR_HEADER *mqtt_var_header; \
    }

typedef struct MQTT_PKT_PUBREC_S
{
    MQTT_PUBREC_PUBLIC_MEMBER;
}MQTT_PKT_PUBREC;

struct MQTT_PKT_PUBREC_S *mqtt_pkt_pubrec_create();

int mqtt_pkt_pubrec_init(struct MQTT_PKT_PUBREC_S *mqtt_pkt_pubrec, unsigned int pkt_id);

struct MQTT_PKT_PUBREC_S  *mqtt_pkt_pubrec_decode(uint8_t *buf, int len);

int destroy_pubrec(struct MQTT_PKT_PUBREC_S *mqtt_pkt_pubrec);

