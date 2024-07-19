

#include <stdint.h>

/* variable header struct*/
#define MQTT_PKT_VAR_HEADER_PUBLIC_MEMBER \
    struct \
    { \
        int (*get_var_header_len)(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header); \
        uint8_t* (*get_var_header)(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header); \
        int (*set_var_header)(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header, uint8_t* var_header); \
        int (*set_var_header_len)(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header, int var_header_len); \
        int (*encode)(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header, uint8_t *buf); \
    }

#define MQTT_PKT_VAR_HEADER_PRIVATE_MEMBER \
    struct \
    { \
        int var_header_len; \
        uint8_t* var_header; \
    }

typedef struct MQTT_PKT_VAR_HEADER_S
{
    MQTT_PKT_VAR_HEADER_PUBLIC_MEMBER;
}MQTT_PKT_VAR_HEADER;

typedef int (*ENCODE_FUNC_VAR)(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header, uint8_t *buf);

#define FUNCTION_TABLE_VAR \
    struct \
    { \
        ENCODE_FUNC_VAR encode; \
    }

typedef struct FUNCTION_TABLES_VAR_S
{
    FUNCTION_TABLE_VAR;
}FUNCTION_TABLES_VAR_HEADER;

extern MQTT_PKT_VAR_HEADER *mqtt_var_header_create();
extern int install_var_headers(MQTT_PKT_VAR_HEADER *mqtt_var_header,FUNCTION_TABLES_VAR_HEADER *functions);
extern int destroy_var_header(MQTT_PKT_VAR_HEADER *mqtt_var_header);