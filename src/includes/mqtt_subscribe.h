#include <stdint.h>


typedef struct TOPIC_QOS_S TOPIC_QOS;

struct TOPIC_QOS_S
{
    int qos;
    char topic[128];
    TOPIC_QOS *next;
};


#define MQTT_PKT_SUBSCRIBE_PUBLIC_MEMBER \
    struct \
    { \
        int (*get_pkt_id)(struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe); \
        int (*set_pkt_id)(struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe, int pkt_id); \
        TOPIC_QOS *(*get_topic)(struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe); \
        int (*add_topic)(struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe, char *topic, int qos); \
        int (*encode)(struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe, uint8_t *buf); \
    }

#define MQTT_PKT_SUBSCRIBE_PRIVATE_MEMBER \
    struct \
    { \
        unsigned int pkt_id; \
        \
        MQTT_PKT_FIXED_HEADER *mqtt_fixed_header; \
        MQTT_PKT_VAR_HEADER *mqtt_var_header; \
        MQTT_PKT_PAYLOAD *mqtt_payload; \
        \
        int topic_count; \
        TOPIC_QOS *topic_qos; \
    }

typedef struct MQTT_PKT_SUBSCRIBE_S
{
    MQTT_PKT_SUBSCRIBE_PUBLIC_MEMBER;
}MQTT_PKT_SUBSCRIBE;

struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe_create(int pkt_id);

int destroy_subscribe(struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe);

int mqtt_pkt_subscribe_init(MQTT_PKT_SUBSCRIBE *mqtt_pkt_subscribe, TOPIC_QOS *topics);

struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe_decode(uint8_t *buf, int len);

