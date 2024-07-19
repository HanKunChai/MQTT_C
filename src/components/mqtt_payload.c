#include "mqtt_payload.h"
#include <stdlib.h>
#include <string.h>

/* payload struct*/
typedef struct MQTT_PKT_PAYLOAD_PRIV_S
{
    MQTT_PKT_PAYLOAD_PUBLIC_MEMBER;
    MQTT_PKT_PAYLOAD_PRIVATE_MEMBER;
}MQTT_PKT_PAYLOAD_PRIV;


static int get_payload_len(struct MQTT_PKT_PAYLOAD_S *mqtt_payload)
{
    MQTT_PKT_PAYLOAD_PRIV *mqtt_payload_priv = (MQTT_PKT_PAYLOAD_PRIV *)mqtt_payload;
    return mqtt_payload_priv->payload_len;
}

static uint8_t* get_payload(struct MQTT_PKT_PAYLOAD_S *mqtt_payload)
{
    MQTT_PKT_PAYLOAD_PRIV *mqtt_payload_priv = (MQTT_PKT_PAYLOAD_PRIV *)mqtt_payload;
    return mqtt_payload_priv->payload;
}


static int set_payload(struct MQTT_PKT_PAYLOAD_S *mqtt_payload, uint8_t* payload)
{
    MQTT_PKT_PAYLOAD_PRIV *mqtt_payload_priv = (MQTT_PKT_PAYLOAD_PRIV *)mqtt_payload;
    mqtt_payload_priv->payload = payload;
    return 0;
}

static int set_payload_len(struct MQTT_PKT_PAYLOAD_S *mqtt_payload, int payload_len)
{
    MQTT_PKT_PAYLOAD_PRIV *mqtt_payload_priv = (MQTT_PKT_PAYLOAD_PRIV *)mqtt_payload;
    mqtt_payload_priv->payload_len = payload_len;
    return 0;
}

static int encode(struct MQTT_PKT_PAYLOAD_S *mqtt_payload, uint8_t *buf)
{
    MQTT_PKT_PAYLOAD_PRIV *mqtt_payload_priv = (MQTT_PKT_PAYLOAD_PRIV *)mqtt_payload;
    memcpy(buf, mqtt_payload_priv->payload, mqtt_payload_priv->payload_len);
    return mqtt_payload_priv->payload_len;
}


MQTT_PKT_PAYLOAD* mqtt_payload_create()
{
    MQTT_PKT_PAYLOAD_PRIV *mqtt_payload_priv = (MQTT_PKT_PAYLOAD_PRIV *)malloc(sizeof(MQTT_PKT_PAYLOAD_PRIV));
    memset(mqtt_payload_priv, 0, sizeof(MQTT_PKT_PAYLOAD_PRIV));
    mqtt_payload_priv->get_payload_len = get_payload_len;
    mqtt_payload_priv->get_payload = get_payload;
    mqtt_payload_priv->set_payload = set_payload;
    mqtt_payload_priv->set_payload_len = set_payload_len;
    mqtt_payload_priv->encode = encode;
    return (MQTT_PKT_PAYLOAD *)mqtt_payload_priv;
}


int install_payloads(MQTT_PKT_PAYLOAD *mqtt_payload,FUNCTION_TABLES_PAYLOAD *functions)
{
    MQTT_PKT_PAYLOAD_PRIV *mqtt_payload_priv = (MQTT_PKT_PAYLOAD_PRIV *)mqtt_payload;
    mqtt_payload_priv->encode = functions->encode;
    return 0;
}

int destroy_payload(MQTT_PKT_PAYLOAD *mqtt_payload)
{
    MQTT_PKT_PAYLOAD_PRIV *mqtt_payload_priv = (MQTT_PKT_PAYLOAD_PRIV *)mqtt_payload;
    free(mqtt_payload_priv);
    return 0;
}