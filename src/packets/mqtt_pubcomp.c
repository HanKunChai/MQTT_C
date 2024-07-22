#include "mqtt_pubcomp.h"
#include "mqtt_fixed_header.h"
#include "mqtt_var_header.h"
#include "encode.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PUBCOMP_TYPE 7


typedef struct MQTT_PKT_PUBCOMP_PRIV_S
{
    MQTT_PKT_PUBCOMP_PUBLIC_MEMBER;
    MQTT_PKT_PUBCOMP_PRIVATE_MEMBER;
}MQTT_PKT_PUBCOMP_PRIV;

static int get_pkt_id(MQTT_PKT_PUBCOMP *mqtt_pkt_pubcomp)
{
    MQTT_PKT_PUBCOMP_PRIV *mqtt_pkt_pubcomp_priv = (MQTT_PKT_PUBCOMP_PRIV *)mqtt_pkt_pubcomp;
    return mqtt_pkt_pubcomp_priv->pkt_id;
}

static int set_pkt_id(MQTT_PKT_PUBCOMP *mqtt_pkt_pubcomp, int pkt_id)
{
    MQTT_PKT_PUBCOMP_PRIV *mqtt_pkt_pubcomp_priv = (MQTT_PKT_PUBCOMP_PRIV *)mqtt_pkt_pubcomp;
    mqtt_pkt_pubcomp_priv->pkt_id = pkt_id;
    return 0;
}

static int encode(MQTT_PKT_PUBCOMP *mqtt_pkt_pubcomp, uint8_t* buf)
{
    MQTT_PKT_PUBCOMP_PRIV *mqtt_pkt_pubcomp_priv = (MQTT_PKT_PUBCOMP_PRIV *)mqtt_pkt_pubcomp;
    if (mqtt_pkt_pubcomp_priv == NULL)
    {
        return -1;
    }

    if (mqtt_pkt_pubcomp_priv->mqtt_fixed_header == NULL || mqtt_pkt_pubcomp_priv->mqtt_var_header == NULL)
    {
        return -1;
    }

    int fixed_header_len = mqtt_pkt_pubcomp_priv->mqtt_fixed_header->encode(mqtt_pkt_pubcomp_priv->mqtt_fixed_header, buf);

    int var_header_len = encode_int(buf+fixed_header_len, mqtt_pkt_pubcomp_priv->pkt_id);

    return fixed_header_len+var_header_len;
}


struct MQTT_PKT_PUBCOMP_S *mqtt_pkt_pubcomp_create()
{
    struct MQTT_PKT_PUBCOMP_PRIV_S *mqtt_pkt_pubcomp_priv = (struct MQTT_PKT_PUBCOMP_PRIV_S *)malloc(sizeof(struct MQTT_PKT_PUBCOMP_PRIV_S));
    if (mqtt_pkt_pubcomp_priv == NULL)
    {
        return NULL;
    }

    mqtt_pkt_pubcomp_priv->get_pkt_id = get_pkt_id;
    mqtt_pkt_pubcomp_priv->set_pkt_id = set_pkt_id;
    mqtt_pkt_pubcomp_priv->encode = encode;

    mqtt_pkt_pubcomp_priv->pkt_id = 0;

    mqtt_pkt_pubcomp_priv->mqtt_fixed_header = mqtt_fixed_header_create();
    if (mqtt_pkt_pubcomp_priv->mqtt_fixed_header == NULL)
    {
        free(mqtt_pkt_pubcomp_priv);
        return NULL;
    }

    mqtt_pkt_pubcomp_priv->mqtt_var_header = mqtt_var_header_create();
    if (mqtt_pkt_pubcomp_priv->mqtt_var_header == NULL)
    {
        destroy_fixed_header(mqtt_pkt_pubcomp_priv->mqtt_fixed_header);
        free(mqtt_pkt_pubcomp_priv);
        return NULL;
    }



    return (struct MQTT_PKT_PUBCOMP_S *)mqtt_pkt_pubcomp_priv;
}


int mqtt_pkt_pubcomp_init(struct MQTT_PKT_PUBCOMP_S *mqtt_pkt_pubcomp, unsigned int pkt_id)
{
    MQTT_PKT_PUBCOMP_PRIV *mqtt_pkt_pubcomp_priv = (MQTT_PKT_PUBCOMP_PRIV *)mqtt_pkt_pubcomp;
    mqtt_pkt_pubcomp_priv->pkt_id = pkt_id;

    mqtt_pkt_pubcomp_priv->mqtt_fixed_header->set_pkt_type(mqtt_pkt_pubcomp_priv->mqtt_fixed_header, PUBCOMP_TYPE);
    mqtt_pkt_pubcomp_priv->mqtt_fixed_header->set_pkt_flag(mqtt_pkt_pubcomp_priv->mqtt_fixed_header, 0x00);

    uint8_t *var_header = malloc(2);

    if (var_header == NULL)
    {
        return -1;
    }

    encode_int(var_header, pkt_id);

    mqtt_pkt_pubcomp_priv->mqtt_var_header->set_var_header(mqtt_pkt_pubcomp_priv->mqtt_var_header, var_header);
    mqtt_pkt_pubcomp_priv->mqtt_fixed_header->set_pkt_rem_len(mqtt_pkt_pubcomp_priv->mqtt_fixed_header, 2);
    mqtt_pkt_pubcomp_priv->mqtt_var_header->set_var_header_len(mqtt_pkt_pubcomp_priv->mqtt_var_header, 2);

    return 0;
}

struct MQTT_PKT_PUBCOMP_S  *mqtt_pkt_pubcomp_decode(uint8_t *buf, int len)
{
    struct MQTT_PKT_PUBCOMP_PRIV_S *mqtt_pkt_pubcomp_priv = (struct MQTT_PKT_PUBCOMP_PRIV_S *)malloc(sizeof(struct MQTT_PKT_PUBCOMP_PRIV_S));
    if (mqtt_pkt_pubcomp_priv == NULL)
    {
        return NULL;
    }

    mqtt_pkt_pubcomp_priv->get_pkt_id = get_pkt_id;
    mqtt_pkt_pubcomp_priv->set_pkt_id = set_pkt_id;
    mqtt_pkt_pubcomp_priv->encode = encode;

    mqtt_pkt_pubcomp_priv->mqtt_fixed_header = mqtt_fixed_header_decode(buf, len);
    if (mqtt_pkt_pubcomp_priv->mqtt_fixed_header == NULL)
    {
        free(mqtt_pkt_pubcomp_priv);
        return NULL;
    }

    mqtt_pkt_pubcomp_priv->mqtt_var_header = mqtt_var_header_create();
    if (mqtt_pkt_pubcomp_priv->mqtt_var_header == NULL)
    {
        destroy_fixed_header(mqtt_pkt_pubcomp_priv->mqtt_fixed_header);
        free(mqtt_pkt_pubcomp_priv);
        return NULL;
    }

    int packet_id = (buf[2] << 8) + buf[3];
    mqtt_pkt_pubcomp_priv->pkt_id = packet_id;

    uint8_t *var_header = malloc(2);
    if (var_header == NULL)
    {
        destroy_fixed_header(mqtt_pkt_pubcomp_priv->mqtt_fixed_header);
        destroy_var_header(mqtt_pkt_pubcomp_priv->mqtt_var_header);
        free(mqtt_pkt_pubcomp_priv);
        return NULL;
    }

    var_header[0] = buf[2];
    var_header[1] = buf[3];

    mqtt_pkt_pubcomp_priv->mqtt_var_header->set_var_header(mqtt_pkt_pubcomp_priv->mqtt_var_header, var_header);
    mqtt_pkt_pubcomp_priv->mqtt_var_header->set_var_header_len(mqtt_pkt_pubcomp_priv->mqtt_var_header, 2);

    return (struct MQTT_PKT_PUBCOMP_S *)mqtt_pkt_pubcomp_priv;
}

int destroy_pubcomp(struct MQTT_PKT_PUBCOMP_S *mqtt_pkt_pubcomp)
{
    MQTT_PKT_PUBCOMP_PRIV *mqtt_pkt_pubcomp_priv = (MQTT_PKT_PUBCOMP_PRIV *)mqtt_pkt_pubcomp;
    if (mqtt_pkt_pubcomp_priv == NULL)
    {
        return -1;
    }

    if (mqtt_pkt_pubcomp_priv->mqtt_fixed_header != NULL)
    {
        destroy_fixed_header(mqtt_pkt_pubcomp_priv->mqtt_fixed_header);
    }

    if (mqtt_pkt_pubcomp_priv->mqtt_var_header != NULL)
    {
        destroy_var_header(mqtt_pkt_pubcomp_priv->mqtt_var_header);
    }

    free(mqtt_pkt_pubcomp_priv);

    return 0;
}


