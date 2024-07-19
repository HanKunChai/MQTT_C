#include <stdint.h>

#define MQTT_CONNACK_FIXED_HEADER_LEN 2
#define MQTT_CONNACK_VAR_HEADER_LEN 2

#define MQTT_CONNACK_PUBLIC_MEMBER \
    struct \
    { \
        unsigned char (*get_session_present)(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack); \
        unsigned char (*get_return_code)(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack); \
        int (*set_session_present)(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack, unsigned char session_present); \
        int (*set_return_code)(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack, unsigned char return_code); \
        int (*encode)(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack, uint8_t *buf); \
    }

#define MQTT_CONNACK_PRIVATE_MEMBER \
    struct \
    { \
        unsigned char session_present; \
        unsigned char return_code; \
        \
        MQTT_PKT_FIXED_HEADER *mqtt_fixed_header; \
        MQTT_PKT_VAR_HEADER *mqtt_var_header; \
    }

typedef struct MQTT_PKT_CONNACK_S
{
    MQTT_CONNACK_PUBLIC_MEMBER;
}MQTT_PKT_CONNACK;

struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack_create();

int mqtt_pkt_connack_init(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack, uint8_t session_present, uint8_t return_code);

struct MQTT_PKT_CONNACK_S  *mqtt_pkt_connack_decode(uint8_t *buf, int len);

int destroy_connack(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack);

