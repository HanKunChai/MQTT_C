#include <stdint.h>

typedef struct MQTT_PKT_PUBLISH_PARAM_S
{
    char topic_name[64];
    char message[128];
    int qos;
    int retain;
    int dup;
    int packet_id;
}MQTT_PKT_PUBLISH_PARAM;

#define MQTT_PKT_PUBLISH_PUBLIC_MEMBER \
    struct \
    { \
        int (*get_param)(struct MQTT_PKT_PUBLISH_S *mqtt_pkt_publish, struct MQTT_PKT_PUBLISH_PARAM_S * param); \
        int (*encode)(struct MQTT_PKT_PUBLISH_S *mqtt_pkt_publish, uint8_t *buf); \
    }

#define MQTT_PKT_PUBLISH_PRIVATE_MEMBER \
    struct \
    { \
        int pkt_len; \
        char topic_name[64]; \
        char message[128]; \
        int qos; \
        int retain; \
        int dup; \
        int packet_id; \
        \
        MQTT_PKT_FIXED_HEADER *mqtt_fixed_header; \
        MQTT_PKT_VAR_HEADER *mqtt_var_header; \
        MQTT_PKT_PAYLOAD *mqtt_payload; \
    }

typedef struct MQTT_PKT_PUBLISH_S
{
    MQTT_PKT_PUBLISH_PUBLIC_MEMBER;
}MQTT_PKT_PUBLISH;

struct MQTT_PKT_PUBLISH_S *mqtt_pkt_publish_decode(uint8_t *buf, int buf_len);

extern MQTT_PKT_PUBLISH *mqtt_pkt_publish_create();

int destroy_publish(MQTT_PKT_PUBLISH *mqtt_pkt_publish);

extern int mqtt_pkt_publish_init(MQTT_PKT_PUBLISH *mqtt_pkt_publish, MQTT_PKT_PUBLISH_PARAM *param);

