#include "mqtt_pubrec.h"
#include "mqtt_fixed_header.h"
#include "mqtt_var_header.h"
#include "encode.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define PUBREC_TYPE 5

typedef struct MQTT_PKT_PUBREC_PRIV_S
{
    MQTT_PUBREC_PUBLIC_MEMBER;
    MQTT_PUBREC_PRIVATE_MEMBER;
}MQTT_PKT_PUBREC_PRIV;

static int get_pkt_id(MQTT_PKT_PUBREC *mqtt_pkt_pubrec)
{
    MQTT_PKT_PUBREC_PRIV *mqtt_pkt_pubrec_priv = (MQTT_PKT_PUBREC_PRIV *)mqtt_pkt_pubrec;
    return mqtt_pkt_pubrec_priv->pkt_id;
}

static int set_pkt_id(MQTT_PKT_PUBREC *mqtt_pkt_pubrec, int pkt_id)
{
    MQTT_PKT_PUBREC_PRIV *mqtt_pkt_pubrec_priv = (MQTT_PKT_PUBREC_PRIV *)mqtt_pkt_pubrec;
    mqtt_pkt_pubrec_priv->pkt_id = pkt_id;
    return 0;
}

static int encode(MQTT_PKT_PUBREC *mqtt_pkt_pubrec, uint8_t* buf)
{
    MQTT_PKT_PUBREC_PRIV *mqtt_pkt_pubrec_priv = (MQTT_PKT_PUBREC_PRIV *)mqtt_pkt_pubrec;
    if (mqtt_pkt_pubrec_priv == NULL)
    {
        return -1;
    }

    if (mqtt_pkt_pubrec_priv->mqtt_fixed_header == NULL || mqtt_pkt_pubrec_priv->mqtt_var_header == NULL)
    {
        return -1;
    }

    int fixed_header_len = mqtt_pkt_pubrec_priv->mqtt_fixed_header->encode(mqtt_pkt_pubrec_priv->mqtt_fixed_header, buf);

    int var_header_len = encode_int(buf+fixed_header_len, mqtt_pkt_pubrec_priv->pkt_id);

    return fixed_header_len+var_header_len;
}

struct MQTT_PKT_PUBREC_S *mqtt_pkt_pubrec_create()
{
    struct MQTT_PKT_PUBREC_PRIV_S *mqtt_pkt_pubrec_priv = (struct MQTT_PKT_PUBREC_PRIV_S *)malloc(sizeof(struct MQTT_PKT_PUBREC_PRIV_S));
    if (mqtt_pkt_pubrec_priv == NULL)
    {
        return NULL;
    }

    mqtt_pkt_pubrec_priv->get_pkt_id = get_pkt_id;
    mqtt_pkt_pubrec_priv->set_pkt_id = set_pkt_id;
    mqtt_pkt_pubrec_priv->encode = encode;

    mqtt_pkt_pubrec_priv->pkt_id = 0;

    mqtt_pkt_pubrec_priv->mqtt_fixed_header = mqtt_fixed_header_create();
    if (mqtt_pkt_pubrec_priv->mqtt_fixed_header == NULL)
    {
        free(mqtt_pkt_pubrec_priv);
        return NULL;
    }

    mqtt_pkt_pubrec_priv->mqtt_fixed_header->set_pkt_type(mqtt_pkt_pubrec_priv->mqtt_fixed_header, PUBREC_TYPE);
    mqtt_pkt_pubrec_priv->mqtt_fixed_header->set_pkt_flag(mqtt_pkt_pubrec_priv->mqtt_fixed_header, 0);

    mqtt_pkt_pubrec_priv->mqtt_var_header = mqtt_var_header_create();
    if (mqtt_pkt_pubrec_priv->mqtt_var_header == NULL)
    {
        destroy_fixed_header(mqtt_pkt_pubrec_priv->mqtt_fixed_header);
        free(mqtt_pkt_pubrec_priv);
        return NULL;
    }

    return (struct MQTT_PKT_PUBREC_S *)mqtt_pkt_pubrec_priv;
}

int mqtt_pkt_pubrec_init(struct MQTT_PKT_PUBREC_S *mqtt_pkt_pubrec, unsigned int pkt_id)
{
    MQTT_PKT_PUBREC_PRIV *mqtt_pkt_pubrec_priv = (MQTT_PKT_PUBREC_PRIV *)mqtt_pkt_pubrec;
    if (mqtt_pkt_pubrec_priv == NULL)
    {
        return -1;
    }

    mqtt_pkt_pubrec_priv->pkt_id = pkt_id;

    mqtt_pkt_pubrec_priv->mqtt_fixed_header = mqtt_fixed_header_create();
    if (mqtt_pkt_pubrec_priv->mqtt_fixed_header == NULL)
    {
        return -1;
    }

    mqtt_pkt_pubrec_priv->mqtt_var_header = mqtt_var_header_create();
    if (mqtt_pkt_pubrec_priv->mqtt_var_header == NULL)
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

    mqtt_pkt_pubrec_priv->mqtt_fixed_header->set_pkt_type(mqtt_pkt_pubrec_priv->mqtt_fixed_header, PUBREC_TYPE);
    mqtt_pkt_pubrec_priv->mqtt_fixed_header->set_pkt_flag(mqtt_pkt_pubrec_priv->mqtt_fixed_header, 0);
    mqtt_pkt_pubrec_priv->mqtt_fixed_header->set_pkt_rem_len(mqtt_pkt_pubrec_priv->mqtt_fixed_header, 2);
    mqtt_pkt_pubrec_priv->mqtt_var_header->set_var_header_len(mqtt_pkt_pubrec_priv->mqtt_var_header, 2);
    mqtt_pkt_pubrec_priv->mqtt_var_header->set_var_header(mqtt_pkt_pubrec_priv->mqtt_var_header, var_header);

    return 0;
}

struct MQTT_PKT_PUBREC_S  *mqtt_pkt_pubrec_decode(uint8_t *buf, int len)
{
    struct MQTT_PKT_PUBREC_PRIV_S *mqtt_pkt_pubrec_priv = (struct MQTT_PKT_PUBREC_PRIV_S *)malloc(sizeof(struct MQTT_PKT_PUBREC_PRIV_S));
    if (mqtt_pkt_pubrec_priv == NULL)
    {
        return NULL;
    }

    mqtt_pkt_pubrec_priv->get_pkt_id = get_pkt_id;
    mqtt_pkt_pubrec_priv->set_pkt_id = set_pkt_id;
    mqtt_pkt_pubrec_priv->encode = encode;

    mqtt_pkt_pubrec_priv->mqtt_fixed_header = mqtt_fixed_header_decode(buf, len);
    if (mqtt_pkt_pubrec_priv->mqtt_fixed_header == NULL)
    {
        free(mqtt_pkt_pubrec_priv);
        return NULL;
    }

    mqtt_pkt_pubrec_priv->mqtt_var_header = mqtt_var_header_create();
    if (mqtt_pkt_pubrec_priv->mqtt_var_header == NULL)
    {
        destroy_fixed_header(mqtt_pkt_pubrec_priv->mqtt_fixed_header);
        free(mqtt_pkt_pubrec_priv);
        return NULL;
    }

    int8_t *var_header = (int8_t *)malloc(2);
    if (var_header == NULL)
    {
        return NULL;
    }

    memcpy(var_header, buf + 2, 2);

    mqtt_pkt_pubrec_priv->mqtt_var_header->set_var_header_len(mqtt_pkt_pubrec_priv->mqtt_var_header, 2);
    mqtt_pkt_pubrec_priv->mqtt_var_header->set_var_header(mqtt_pkt_pubrec_priv->mqtt_var_header, var_header);

    mqtt_pkt_pubrec_priv->pkt_id = (buf[2] << 8) + buf[3];

    return (struct MQTT_PKT_PUBREC_S *)mqtt_pkt_pubrec_priv;

}

int destroy_pubrec(struct MQTT_PKT_PUBREC_S *mqtt_pkt_pubrec)
{
    MQTT_PKT_PUBREC_PRIV *mqtt_pkt_pubrec_priv = (MQTT_PKT_PUBREC_PRIV *)mqtt_pkt_pubrec;
    if (mqtt_pkt_pubrec_priv == NULL)
    {
        return -1;
    }

    if (mqtt_pkt_pubrec_priv->mqtt_fixed_header != NULL)
    {
        destroy_fixed_header(mqtt_pkt_pubrec_priv->mqtt_fixed_header);
    }

    if (mqtt_pkt_pubrec_priv->mqtt_var_header != NULL)
    {
        destroy_var_header(mqtt_pkt_pubrec_priv->mqtt_var_header);
    }

    free(mqtt_pkt_pubrec_priv);

    return 0;
}



