#include "mqtt_fixed_header.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "encode.h"

/* fixed header struct*/
typedef struct MQTT_PKT_FIXED_HEADER_PRIV_S
{
    MQTT_PKT_FIXED_HEADER_PUBLIC_MEMBER;
    MQTT_PKT_FIXED_HEADER_PRIVATE_MEMBER;
}MQTT_PKT_FIXED_HEADER_PRIV;


static int get_pkt_len(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header)
{
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)mqtt_fixed_header;
    return mqtt_fixed_header_priv->pkt_len;
}

static uint8_t get_pkt_type(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header)
{
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)mqtt_fixed_header;
    return mqtt_fixed_header_priv->pkt_type;
}

static uint8_t get_pkt_flag(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header)
{
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)mqtt_fixed_header;
    return mqtt_fixed_header_priv->pkt_flag;
}

static int get_pkt_rem_len(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header)
{
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)mqtt_fixed_header;
    return mqtt_fixed_header_priv->pkt_rem_len;
}

static int set_pkt_type(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header, uint8_t type)
{
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)mqtt_fixed_header;
    mqtt_fixed_header_priv->pkt_type = type;
    return 0;
}

static int set_pkt_flag(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header, uint8_t flag)
{
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)mqtt_fixed_header;
    mqtt_fixed_header_priv->pkt_flag = flag;
    return 0;
}

static int set_pkt_rem_len(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header, int rem_len)
{
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)mqtt_fixed_header;

    mqtt_fixed_header_priv->pkt_rem_len = rem_len;
    return 0;
}


static int encode(struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header, uint8_t *buf)
{
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)mqtt_fixed_header;
    buf[0] = (mqtt_fixed_header_priv->pkt_type << 4) | (mqtt_fixed_header_priv->pkt_flag & 0x0F);
    
    int fixed_header_len = encode_rem_len(mqtt_fixed_header_priv->pkt_rem_len, buf + 1);
    mqtt_fixed_header_priv->pkt_len = fixed_header_len + 1;
    return mqtt_fixed_header_priv->pkt_len;
}

MQTT_PKT_FIXED_HEADER* mqtt_fixed_header_create()
{
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)malloc(sizeof(MQTT_PKT_FIXED_HEADER_PRIV));
    mqtt_fixed_header_priv->get_pkt_len = get_pkt_len;
    mqtt_fixed_header_priv->get_pkt_type = get_pkt_type;
    mqtt_fixed_header_priv->get_pkt_flag = get_pkt_flag;
    mqtt_fixed_header_priv->get_pkt_rem_len = get_pkt_rem_len;
    mqtt_fixed_header_priv->set_pkt_type = set_pkt_type;
    mqtt_fixed_header_priv->set_pkt_flag = set_pkt_flag;
    mqtt_fixed_header_priv->set_pkt_rem_len = set_pkt_rem_len;
    mqtt_fixed_header_priv->encode = encode;
    mqtt_fixed_header_priv->pkt_len = MQTT_FIX_HEADER_LEN;
    return (MQTT_PKT_FIXED_HEADER *)mqtt_fixed_header_priv;
}

struct MQTT_PKT_FIXED_HEADER_S* mqtt_fixed_header_decode(uint8_t *buf, int len)
{
    if (buf == NULL || len < 2)
    {
        return NULL;
    }

    /*init*/    
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)malloc(sizeof(MQTT_PKT_FIXED_HEADER_PRIV));
    mqtt_fixed_header_priv->get_pkt_len = get_pkt_len;
    mqtt_fixed_header_priv->get_pkt_type = get_pkt_type;
    mqtt_fixed_header_priv->get_pkt_flag = get_pkt_flag;
    mqtt_fixed_header_priv->get_pkt_rem_len = get_pkt_rem_len;
    mqtt_fixed_header_priv->set_pkt_type = set_pkt_type;
    mqtt_fixed_header_priv->set_pkt_flag = set_pkt_flag;
    mqtt_fixed_header_priv->set_pkt_rem_len = set_pkt_rem_len;
    mqtt_fixed_header_priv->encode = encode;
    
    /*decode*/
    mqtt_fixed_header_priv->pkt_type = buf[0] >> 4;
    mqtt_fixed_header_priv->pkt_flag = buf[0] & 0x0F;
    mqtt_fixed_header_priv->pkt_rem_len = 0;
    int rem_len_len = decode_rem_len(buf + 1, &mqtt_fixed_header_priv->pkt_rem_len);
    mqtt_fixed_header_priv->pkt_len = rem_len_len + 1;    
    return (MQTT_PKT_FIXED_HEADER *)mqtt_fixed_header_priv;
}


int destroy_fixed_header(MQTT_PKT_FIXED_HEADER *mqtt_fixed_header)
{
    MQTT_PKT_FIXED_HEADER_PRIV *mqtt_fixed_header_priv = (MQTT_PKT_FIXED_HEADER_PRIV *)mqtt_fixed_header;
    free(mqtt_fixed_header_priv);
    return 0;
}