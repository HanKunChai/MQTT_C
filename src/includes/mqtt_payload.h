
#include <stdint.h>

/* payload struct*/
#define MQTT_PKT_PAYLOAD_PUBLIC_MEMBER \
    struct \
    { \
        int (*get_payload_len)(struct MQTT_PKT_PAYLOAD_S *mqtt_payload); \
        uint8_t* (*get_payload)(struct MQTT_PKT_PAYLOAD_S *mqtt_payload); \
        int (*set_payload_len)(struct MQTT_PKT_PAYLOAD_S *mqtt_payload, int payload_len); \
        int (*set_payload)(struct MQTT_PKT_PAYLOAD_S *mqtt_payload, uint8_t* payload); \
        int (*encode)(struct MQTT_PKT_PAYLOAD_S *mqtt_payload, uint8_t *buf); \
    }

#define MQTT_PKT_PAYLOAD_PRIVATE_MEMBER \
    struct \
    { \
        int payload_len; \
        uint8_t* payload; \
    }

typedef struct MQTT_PKT_PAYLOAD_S
{
    MQTT_PKT_PAYLOAD_PUBLIC_MEMBER;
}MQTT_PKT_PAYLOAD;

typedef int (*ENCODE_FUNC_PAYLOAD)(struct MQTT_PKT_PAYLOAD_S *mqtt_payload, uint8_t *buf);

#define FUNCTION_TABLE_PAYLOAD \
    struct \
    { \
        ENCODE_FUNC_PAYLOAD encode; \
    }

typedef struct FUNCTION_TABLES_PAYLOAD_S
{
    FUNCTION_TABLE_PAYLOAD;
}FUNCTION_TABLES_PAYLOAD;

extern MQTT_PKT_PAYLOAD* mqtt_payload_create();
extern int install_payloads(MQTT_PKT_PAYLOAD *mqtt_payload, FUNCTION_TABLES_PAYLOAD *functions);
extern int destroy_payload(MQTT_PKT_PAYLOAD *mqtt_payload);
