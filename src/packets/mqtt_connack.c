#include "mqtt_connack.h"
#include "mqtt_fixed_header.h"
#include "mqtt_var_header.h"
#include "encode.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct MQTT_PKT_CONNACK_PRIV_S
{
    MQTT_CONNACK_PUBLIC_MEMBER;
    MQTT_CONNACK_PRIVATE_MEMBER;
}MQTT_PKT_CONNACK_PRIV;

#define MQTT_CONNACK 2


static uint8_t get_session_present(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack)
{
    MQTT_PKT_CONNACK_PRIV *mqtt_pkt_connack_priv = (MQTT_PKT_CONNACK_PRIV *)mqtt_pkt_connack;
    return mqtt_pkt_connack_priv->session_present;
}

static uint8_t get_return_code(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack)
{
    MQTT_PKT_CONNACK_PRIV *mqtt_pkt_connack_priv = (MQTT_PKT_CONNACK_PRIV *)mqtt_pkt_connack;
    return mqtt_pkt_connack_priv->return_code;
}

static int set_session_present(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack, unsigned char session_present)
{
    MQTT_PKT_CONNACK_PRIV *mqtt_pkt_connack_priv = (MQTT_PKT_CONNACK_PRIV *)mqtt_pkt_connack;
    mqtt_pkt_connack_priv->session_present = session_present;
    return 0;
}

static int set_return_code(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack, unsigned char return_code)
{
    MQTT_PKT_CONNACK_PRIV *mqtt_pkt_connack_priv = (MQTT_PKT_CONNACK_PRIV *)mqtt_pkt_connack;
    mqtt_pkt_connack_priv->return_code = return_code;
    return 0;
}

static int encode(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack, uint8_t *buf)
{
    MQTT_PKT_CONNACK_PRIV *mqtt_pkt_connack_priv = (MQTT_PKT_CONNACK_PRIV *)mqtt_pkt_connack;
    MQTT_PKT_FIXED_HEADER *mqtt_fixed_header = mqtt_pkt_connack_priv->mqtt_fixed_header;
    MQTT_PKT_VAR_HEADER *mqtt_var_header = mqtt_pkt_connack_priv->mqtt_var_header;
    int buf_len = 0;
    int fixed_header_len = 0;
    int var_header_len = 0;
    int i = 0;
    uint8_t *buf_ptr = buf;

    fixed_header_len = mqtt_fixed_header->encode(mqtt_fixed_header, buf_ptr);
    buf_ptr += fixed_header_len;

    var_header_len = mqtt_var_header->encode(mqtt_var_header, buf_ptr);
    buf_ptr += var_header_len;

    buf_len = fixed_header_len + var_header_len;

    return buf_len;
}

int mqtt_pkt_connack_init(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack, uint8_t session_present, uint8_t return_code)
{
    MQTT_PKT_CONNACK_PRIV *mqtt_pkt_connack_priv = (MQTT_PKT_CONNACK_PRIV *)mqtt_pkt_connack;
    mqtt_pkt_connack_priv->session_present = session_present;
    mqtt_pkt_connack_priv->return_code = return_code;

    MQTT_PKT_FIXED_HEADER *mqtt_fixed_header = mqtt_pkt_connack_priv->mqtt_fixed_header;
    mqtt_fixed_header->set_pkt_type(mqtt_fixed_header, MQTT_CONNACK);
    mqtt_fixed_header->set_pkt_flag(mqtt_fixed_header, 0);

    MQTT_PKT_VAR_HEADER *mqtt_connack_var_header = mqtt_pkt_connack_priv->mqtt_var_header;
    mqtt_connack_var_header->set_var_header_len(mqtt_connack_var_header, MQTT_CONNACK_VAR_HEADER_LEN);

    uint8_t *var_header = (uint8_t *)malloc(MQTT_CONNACK_VAR_HEADER_LEN);
    var_header[0] = session_present;
    var_header[1] = return_code;

    mqtt_fixed_header->set_pkt_rem_len(mqtt_fixed_header, MQTT_CONNACK_VAR_HEADER_LEN);

    mqtt_connack_var_header->set_var_header(mqtt_connack_var_header, var_header);

    return 0;
}


struct MQTT_PKT_CONNACK_S* mqtt_pkt_connack_create()
{
    MQTT_PKT_CONNACK_PRIV *mqtt_pkt_connack_priv = (MQTT_PKT_CONNACK_PRIV *)malloc(sizeof(MQTT_PKT_CONNACK_PRIV));
    memset(mqtt_pkt_connack_priv, 0, sizeof(MQTT_PKT_CONNACK_PRIV));

    mqtt_pkt_connack_priv->get_session_present = get_session_present;
    mqtt_pkt_connack_priv->get_return_code = get_return_code;
    mqtt_pkt_connack_priv->set_session_present = set_session_present;
    mqtt_pkt_connack_priv->set_return_code = set_return_code;
    mqtt_pkt_connack_priv->encode = encode;

    mqtt_pkt_connack_priv->mqtt_fixed_header = mqtt_fixed_header_create();
    mqtt_pkt_connack_priv->mqtt_var_header = mqtt_var_header_create();

    return (MQTT_PKT_CONNACK*)mqtt_pkt_connack_priv;
}

struct MQTT_PKT_VAR_HEADER_S *mqtt_connack_var_header_decode(uint8_t *buf, int buf_len)
{
    MQTT_PKT_VAR_HEADER *mqtt_var_header = mqtt_var_header_create();
    mqtt_var_header->set_var_header_len(mqtt_var_header, MQTT_CONNACK_VAR_HEADER_LEN);

    uint8_t *var_header = (uint8_t *)malloc(MQTT_CONNACK_VAR_HEADER_LEN);
    memcpy(var_header, buf, MQTT_CONNACK_VAR_HEADER_LEN);

    mqtt_var_header->set_var_header(mqtt_var_header, var_header);

    return mqtt_var_header;
}


struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack_decode(uint8_t *buf, int buf_len)
{
    MQTT_PKT_CONNACK_PRIV *mqtt_pkt_connack_priv = (MQTT_PKT_CONNACK_PRIV *)malloc(sizeof(MQTT_PKT_CONNACK_PRIV));
    memset(mqtt_pkt_connack_priv, 0, sizeof(MQTT_PKT_CONNACK_PRIV));

    mqtt_pkt_connack_priv->get_session_present = get_session_present;
    mqtt_pkt_connack_priv->get_return_code = get_return_code;
    mqtt_pkt_connack_priv->set_session_present = set_session_present;
    mqtt_pkt_connack_priv->set_return_code = set_return_code;
    mqtt_pkt_connack_priv->encode = encode;

    uint8_t * buf_ptr = buf;
    int buf_rem_len = buf_len;

    struct MQTT_PKT_FIXED_HEADER_S *mqtt_fixed_header = mqtt_fixed_header_decode(buf, buf_len);
    int fixed_header_len = mqtt_fixed_header->get_pkt_len(mqtt_fixed_header);
    buf_ptr += fixed_header_len;
    buf_rem_len -= fixed_header_len;

    struct MQTT_PKT_VAR_HEADER_S *mqtt_var_header = mqtt_connack_var_header_decode(buf_ptr, buf_rem_len);

    mqtt_pkt_connack_priv->mqtt_fixed_header = mqtt_fixed_header;
    mqtt_pkt_connack_priv->mqtt_var_header = mqtt_var_header;
    mqtt_pkt_connack_priv->session_present = mqtt_var_header->get_var_header(mqtt_var_header)[0];
    mqtt_pkt_connack_priv->return_code = mqtt_var_header->get_var_header(mqtt_var_header)[1];   

    return (MQTT_PKT_CONNACK*)mqtt_pkt_connack_priv;
}



int destroy_connack(struct MQTT_PKT_CONNACK_S *mqtt_pkt_connack)
{
    MQTT_PKT_CONNACK_PRIV *mqtt_pkt_connack_priv = (MQTT_PKT_CONNACK_PRIV *)mqtt_pkt_connack;
    destroy_fixed_header(mqtt_pkt_connack_priv->mqtt_fixed_header);
    destroy_var_header(mqtt_pkt_connack_priv->mqtt_var_header);
    free(mqtt_pkt_connack_priv);
    return 0;
}