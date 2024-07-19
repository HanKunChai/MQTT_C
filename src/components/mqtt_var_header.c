#include "mqtt_var_header.h"
#include <stdlib.h>
#include <string.h>

/* variable header struct*/
typedef struct MQTT_PKT_VAR_HEADER_PRIV_S
{
    MQTT_PKT_VAR_HEADER_PUBLIC_MEMBER;
    MQTT_PKT_VAR_HEADER_PRIVATE_MEMBER;
}MQTT_PKT_VAR_HEADER_PRIV;


static int get_var_header_len(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header)
{
    MQTT_PKT_VAR_HEADER_PRIV *mqtt_var_header_priv = (MQTT_PKT_VAR_HEADER_PRIV *)mqtt_var_header;
    return mqtt_var_header_priv->var_header_len;
}

static uint8_t* get_var_header(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header)
{
    MQTT_PKT_VAR_HEADER_PRIV *mqtt_var_header_priv = (MQTT_PKT_VAR_HEADER_PRIV *)mqtt_var_header;
    return mqtt_var_header_priv->var_header;
}

static int set_var_header(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header, uint8_t* var_header)
{
    MQTT_PKT_VAR_HEADER_PRIV *mqtt_var_header_priv = (MQTT_PKT_VAR_HEADER_PRIV *)mqtt_var_header;
    mqtt_var_header_priv->var_header = var_header;
    return 0;
}

static int set_var_header_len(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header, int var_header_len)
{
    MQTT_PKT_VAR_HEADER_PRIV *mqtt_var_header_priv = (MQTT_PKT_VAR_HEADER_PRIV *)mqtt_var_header;
    mqtt_var_header_priv->var_header_len = var_header_len;
    return 0;
}

static int encode(struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header, uint8_t *buf)
{
    MQTT_PKT_VAR_HEADER_PRIV *mqtt_var_header_priv = (MQTT_PKT_VAR_HEADER_PRIV *)mqtt_var_header;
    memcpy(buf, mqtt_var_header_priv->var_header, mqtt_var_header_priv->var_header_len);
    return mqtt_var_header_priv->var_header_len;
}


MQTT_PKT_VAR_HEADER* mqtt_var_header_create()
{
    MQTT_PKT_VAR_HEADER_PRIV *mqtt_var_header_priv = (MQTT_PKT_VAR_HEADER_PRIV *)malloc(sizeof(MQTT_PKT_VAR_HEADER_PRIV));
    mqtt_var_header_priv->get_var_header_len = get_var_header_len;
    mqtt_var_header_priv->set_var_header_len = set_var_header_len;
    mqtt_var_header_priv->get_var_header = get_var_header;
    mqtt_var_header_priv->set_var_header = set_var_header;
    mqtt_var_header_priv->encode = encode;
    return (MQTT_PKT_VAR_HEADER *)mqtt_var_header_priv;
}


int install_var_headers(MQTT_PKT_VAR_HEADER *mqtt_var_header,FUNCTION_TABLES_VAR_HEADER *functions)
{
    MQTT_PKT_VAR_HEADER_PRIV *mqtt_var_header_priv = (MQTT_PKT_VAR_HEADER_PRIV *)mqtt_var_header;
    mqtt_var_header_priv->encode = functions->encode;
    return 0;
}


int destroy_var_header(MQTT_PKT_VAR_HEADER *mqtt_var_header)
{
    MQTT_PKT_VAR_HEADER_PRIV *mqtt_var_header_priv = (MQTT_PKT_VAR_HEADER_PRIV *)mqtt_var_header;
    free(mqtt_var_header_priv);
    return 0;
}