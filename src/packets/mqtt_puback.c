#include "mqtt_puback.h"
#include "mqtt_fixed_header.h"
#include "mqtt_var_header.h"
#include "mqtt_payload.h"
#include "encode.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PUBACK_TYPE 4

typedef struct MQTT_PKT_PUBACK_PRIV_S
{
    MQTT_PUBACK_PUBLIC_MEMBER;
    MQTT_PUBACK_PRIVATE_MEMBER;
}MQTT_PKT_PUBACK_PRIV;



static int get_pkt_id(MQTT_PKT_PUBACK *mqtt_pkt_puback)
{
    MQTT_PKT_PUBACK_PRIV *mqtt_pkt_puback_priv = (MQTT_PKT_PUBACK_PRIV *)mqtt_pkt_puback;
    return mqtt_pkt_puback_priv->pkt_id;
}

static int set_pkt_id(MQTT_PKT_PUBACK *mqtt_pkt_puback, int pkt_id)
{
    MQTT_PKT_PUBACK_PRIV *mqtt_pkt_puback_priv = (MQTT_PKT_PUBACK_PRIV *)mqtt_pkt_puback;
    mqtt_pkt_puback_priv->pkt_id = pkt_id;
    return 0;
}

static int encode(MQTT_PKT_PUBACK *mqtt_pkt_puback, uint8_t* buf)
{
    MQTT_PKT_PUBACK_PRIV *mqtt_pkt_puback_priv = (MQTT_PKT_PUBACK_PRIV *)mqtt_pkt_puback;
    if (mqtt_pkt_puback_priv == NULL)
    {
        return -1;
    }

    if (mqtt_pkt_puback_priv->mqtt_fixed_header == NULL || mqtt_pkt_puback_priv->mqtt_var_header == NULL)
    {
        return -1;
    }

    int fixed_header_len = mqtt_pkt_puback_priv->mqtt_fixed_header->encode(mqtt_pkt_puback_priv->mqtt_fixed_header, buf);

    int var_header_len = encode_int(buf+fixed_header_len, mqtt_pkt_puback_priv->pkt_id);

    return fixed_header_len+var_header_len;
}


struct MQTT_PKT_PUBACK_S *mqtt_pkt_puback_create()
{
    struct MQTT_PKT_PUBACK_PRIV_S *mqtt_pkt_puback_priv = (struct MQTT_PKT_PUBACK_PRIV_S *)malloc(sizeof(struct MQTT_PKT_PUBACK_PRIV_S));
    if (mqtt_pkt_puback_priv == NULL)
    {
        return NULL;
    }

    memset(mqtt_pkt_puback_priv, 0, sizeof(struct MQTT_PKT_PUBACK_S));

    mqtt_pkt_puback_priv->get_pkt_id = get_pkt_id;
    mqtt_pkt_puback_priv->set_pkt_id = set_pkt_id;
    mqtt_pkt_puback_priv->encode = encode;
    return (struct MQTT_PKT_PUBACK_S *)mqtt_pkt_puback_priv;
}

int mqtt_pkt_puback_init(struct MQTT_PKT_PUBACK_S *mqtt_pkt_puback, uint16_t pkt_id)
{
    MQTT_PKT_PUBACK_PRIV *mqtt_pkt_puback_priv = (MQTT_PKT_PUBACK_PRIV *)mqtt_pkt_puback;
    if (mqtt_pkt_puback_priv == NULL)
    {
        return -1;
    }

    mqtt_pkt_puback_priv->pkt_id = pkt_id;

    mqtt_pkt_puback_priv->mqtt_fixed_header = mqtt_fixed_header_create();
    if (mqtt_pkt_puback_priv->mqtt_fixed_header == NULL)
    {
        return -1;
    }

    mqtt_pkt_puback_priv->mqtt_var_header = mqtt_var_header_create();
    if (mqtt_pkt_puback_priv->mqtt_var_header == NULL)
    {
        return -1;
    }

    uint8_t *var_header = (uint8_t *)malloc(2);
    if (var_header == NULL)
    {
        return -1;
    }

    var_header[0] = (pkt_id >> 8) & 0xff;
    var_header[1] = pkt_id & 0xff;

    mqtt_pkt_puback_priv->mqtt_fixed_header->set_pkt_type(mqtt_pkt_puback_priv->mqtt_fixed_header, PUBACK_TYPE);
    mqtt_pkt_puback_priv->mqtt_fixed_header->set_pkt_flag(mqtt_pkt_puback_priv->mqtt_fixed_header, 0);
    mqtt_pkt_puback_priv->mqtt_fixed_header->set_pkt_rem_len(mqtt_pkt_puback_priv->mqtt_fixed_header, 2);
    mqtt_pkt_puback_priv->mqtt_var_header->set_var_header_len(mqtt_pkt_puback_priv->mqtt_var_header, 2);
    mqtt_pkt_puback_priv->mqtt_var_header->set_var_header(mqtt_pkt_puback_priv->mqtt_var_header, var_header);

    return 0;
}

struct MQTT_PKT_PUBACK_S  *mqtt_pkt_puback_decode(uint8_t *buf, int len)
{
    struct MQTT_PKT_PUBACK_PRIV_S *mqtt_pkt_puback_priv = (struct MQTT_PKT_PUBACK_PRIV_S *)malloc(sizeof(struct MQTT_PKT_PUBACK_PRIV_S));
    if (mqtt_pkt_puback_priv == NULL)
    {
        return NULL;
    }

    memset(mqtt_pkt_puback_priv, 0, sizeof(struct MQTT_PKT_PUBACK_S));

    mqtt_pkt_puback_priv->get_pkt_id = get_pkt_id;
    mqtt_pkt_puback_priv->set_pkt_id = set_pkt_id;
    mqtt_pkt_puback_priv->encode = encode;

    mqtt_pkt_puback_priv->mqtt_fixed_header = mqtt_fixed_header_decode(buf, len);
    if (mqtt_pkt_puback_priv->mqtt_fixed_header == NULL)
    {
        return NULL;
    }

    mqtt_pkt_puback_priv->mqtt_var_header = mqtt_var_header_create();
    if (mqtt_pkt_puback_priv->mqtt_var_header == NULL)
    {
        return NULL;
    }

    int8_t *var_header = (int8_t *)malloc(2);
    if (var_header == NULL)
    {
        return NULL;
    }

    memcpy(var_header, buf + 2, 2);

    mqtt_pkt_puback_priv->mqtt_var_header->set_var_header_len(mqtt_pkt_puback_priv->mqtt_var_header, 2);
    mqtt_pkt_puback_priv->mqtt_var_header->set_var_header(mqtt_pkt_puback_priv->mqtt_var_header, var_header);
    
    mqtt_pkt_puback_priv->pkt_id = (buf[2] << 8) + buf[3];

    return (struct MQTT_PKT_PUBACK_S *)mqtt_pkt_puback_priv;
}

int destroy_puback(struct MQTT_PKT_PUBACK_S *mqtt_pkt_puback)
{
    struct MQTT_PKT_PUBACK_PRIV_S *mqtt_pkt_puback_priv = (struct MQTT_PKT_PUBACK_PRIV_S *)mqtt_pkt_puback;
    if (mqtt_pkt_puback_priv == NULL)
    {
        return -1;
    }

    if (mqtt_pkt_puback_priv->mqtt_fixed_header != NULL)
    {
        destroy_fixed_header(mqtt_pkt_puback_priv->mqtt_fixed_header);
    }

    if (mqtt_pkt_puback_priv->mqtt_var_header != NULL)
    {
        destroy_var_header(mqtt_pkt_puback_priv->mqtt_var_header);
    }

    free(mqtt_pkt_puback_priv);
    return 0;
}