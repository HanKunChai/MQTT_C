#include <stdint.h>

#define MQTT_CONNECT_FIXED_HEADER_LEN 2
#define MQTT_CONNECT_VAR_HEADER_MAX_LEN 12


typedef struct MQTT_CONNECT_PARAM_S
{
    char protocol_name[8];
    uint8_t protocol_level;
    uint8_t connect_flag;
    int keep_alive;
    char client_id[32];
    char will_topic[32];
    char will_message[128];
    char user_name[64];
    char password[64];
}MQTT_CONNECT_PARAM;

#define MQTT_PKT_CONNECT_PUBLIC_MEMBER \
    struct \
    { \
        int (*get_param)(struct MQTT_PKT_CONNECT_S *mqtt_pkt_connect, struct MQTT_CONNECT_PARAM_S * param); \
        int (*encode)(struct MQTT_PKT_CONNECT_S *mqtt_pkt_connect, uint8_t *buf); \
    }


#define MQTT_PKT_CONNECT_PRIVATE_MEMBER \
    struct \
    { \
        int pkt_len; \
        char protocol_name[8]; \
        uint8_t protocol_level; \
        uint8_t connect_flag; \
        int keep_alive; \
        char client_id[32]; \
        char will_topic[32]; \
        char will_message[128]; \
        char user_name[64]; \
        char password[64]; \
        \
        MQTT_PKT_FIXED_HEADER *mqtt_fixed_header; \
        MQTT_PKT_VAR_HEADER *mqtt_var_header; \
        MQTT_PKT_PAYLOAD *mqtt_payload; \
    }

typedef struct MQTT_PKT_CONNECT_S
{
    MQTT_PKT_CONNECT_PUBLIC_MEMBER;
}MQTT_PKT_CONNECT;

struct MQTT_PKT_CONNECT_S *mqtt_pkt_connect_decode(uint8_t *buf, int buf_len);

extern MQTT_PKT_CONNECT *mqtt_pkt_connect_create();

int destroy_connect(MQTT_PKT_CONNECT *mqtt_pkt_connect);

extern int mqtt_pkt_connect_init(MQTT_PKT_CONNECT *mqtt_pkt_connect, MQTT_CONNECT_PARAM *param);