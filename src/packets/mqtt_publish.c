#include "mqtt_publish.h"
#include "mqtt_fixed_header.h"
#include "mqtt_var_header.h"
#include "mqtt_payload.h"
#include "encode.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define PUBLISH_TYPE 3

typedef struct MQTT_PKT_PUBLISH_PRIV_S
{
    MQTT_PKT_PUBLISH_PUBLIC_MEMBER;
    MQTT_PKT_PUBLISH_PRIVATE_MEMBER;
}MQTT_PKT_PUBLISH_PRIV;

static int get_param(struct MQTT_PKT_PUBLISH_S *mqtt_pkt_publish, struct MQTT_PKT_PUBLISH_PARAM_S * param)
{
    MQTT_PKT_PUBLISH_PRIV *mqtt_pkt_publish_priv = (MQTT_PKT_PUBLISH_PRIV *)mqtt_pkt_publish;
    if(mqtt_pkt_publish_priv == NULL || param == NULL)
    {
        return -1;
    }

    snprintf(param->topic_name, sizeof(param->topic_name), "%s", mqtt_pkt_publish_priv->topic_name);
    snprintf(param->message, sizeof(param->message), "%s", mqtt_pkt_publish_priv->message);
    param->qos = mqtt_pkt_publish_priv->qos;
    param->retain = mqtt_pkt_publish_priv->retain;
    param->dup = mqtt_pkt_publish_priv->dup;
    param->packet_id = mqtt_pkt_publish_priv->packet_id;

    return 0;
}

static int encode(struct MQTT_PKT_PUBLISH_S *mqtt_pkt_publish, uint8_t *buf)
{
    MQTT_PKT_PUBLISH_PRIV *mqtt_pkt_publish_priv = (MQTT_PKT_PUBLISH_PRIV *)mqtt_pkt_publish;
    if(mqtt_pkt_publish_priv == NULL || buf == NULL)
    {
        return -1;
    }

    int len = 0;
    int ret = 0;
    uint8_t *ptr = buf;

    int fixed_header_len = mqtt_pkt_publish_priv->mqtt_fixed_header->encode(mqtt_pkt_publish_priv->mqtt_fixed_header, ptr);
    if(fixed_header_len < 0)
    {
        return -1;
    }
    ptr += fixed_header_len;
    len += fixed_header_len;

    int var_header_len = mqtt_pkt_publish_priv->mqtt_var_header->encode(mqtt_pkt_publish_priv->mqtt_var_header, ptr);
    if(var_header_len < 0)
    {
        return -1;
    }
    ptr += var_header_len;
    len += var_header_len;

    int payload_len = mqtt_pkt_publish_priv->mqtt_payload->encode(mqtt_pkt_publish_priv->mqtt_payload, ptr);
    if(payload_len < 0)
    {
        return -1;
    }
    ptr += payload_len;
    len += payload_len;

    return len;
}

static MQTT_PKT_FIXED_HEADER* mqtt_publish_fixed_header_decode(MQTT_PKT_PUBLISH_PRIV* mqtt_pkt_publish_priv, 
                                    uint8_t *buf, int buf_len)
{
    MQTT_PKT_FIXED_HEADER *mqtt_fixed_header = mqtt_fixed_header_decode(buf, buf_len);
    if(mqtt_fixed_header == NULL)
    {
        return NULL;
    }

    uint8_t *ptr = buf;
    int len = 0;
    int ret = 0;

    mqtt_pkt_publish_priv->dup = (*ptr >> 3) & 0x1;
    mqtt_pkt_publish_priv->qos = (*ptr >> 1) & 0x3;
    mqtt_pkt_publish_priv->retain = *ptr & 0x1;

    return mqtt_fixed_header;
}

static MQTT_PKT_VAR_HEADER* mqtt_publish_var_header_decode(MQTT_PKT_PUBLISH_PRIV *mqtt_pkt_publish_priv,
    uint8_t *buf, int buf_len, int qos)
{
    MQTT_PKT_VAR_HEADER *mqtt_var_header = mqtt_var_header_create();
    if(mqtt_var_header == NULL)
    {
        return NULL;
    }

    uint8_t *ptr = buf;
    int len = 0;
    int ret = 0;

    int topic_len = 0;
    char topic_name[64] = {0};

    topic_len = decode_string(ptr, topic_name);
    ptr += topic_len;
    len += topic_len;
    snprintf(mqtt_pkt_publish_priv->topic_name, sizeof(mqtt_pkt_publish_priv->topic_name), "%s", topic_name);

    int packet_id = 0;
    int packet_id_len = 0;
    if (qos > 0)
    {
        packet_id_len = decode_len(ptr, &packet_id);
        ptr += packet_id_len;
        len += packet_id_len;
        
    }
    mqtt_pkt_publish_priv->packet_id = packet_id;

    uint8_t *var_header = (uint8_t *)malloc(len);
    memcpy(var_header, buf, len);
    mqtt_var_header->set_var_header_len(mqtt_var_header, len);
    mqtt_var_header->set_var_header(mqtt_var_header, var_header);
    
    return mqtt_var_header;
}

static MQTT_PKT_PAYLOAD* mqtt_publish_payload_decode(MQTT_PKT_PUBLISH_PRIV *mqtt_pkt_publish_priv, uint8_t *buf, int buf_len)
{
    MQTT_PKT_PAYLOAD *mqtt_payload = mqtt_payload_create();
    if(mqtt_payload == NULL || buf_len == 0 || buf == NULL)
    {
        return NULL;
    }

    uint8_t *ptr = buf;
    int len = 0;
    int ret = 0;

    int payload_len = 0;
    char message[128] = {0};

    payload_len = decode_string(ptr, message);
    ptr += payload_len;
    len += payload_len;
    snprintf(mqtt_pkt_publish_priv->message, sizeof(mqtt_pkt_publish_priv->message), "%s", message);

    uint8_t *payload = (uint8_t *)malloc(len);
    memcpy(payload, buf, len);
    mqtt_payload->set_payload_len(mqtt_payload, len);
    mqtt_payload->set_payload(mqtt_payload, payload);

    return mqtt_payload;
}


struct MQTT_PKT_PUBLISH_S *mqtt_pkt_publish_decode(uint8_t *buf, int buf_len)
{
    MQTT_PKT_PUBLISH_PRIV *mqtt_pkt_publish_priv = (MQTT_PKT_PUBLISH_PRIV *)malloc(sizeof(MQTT_PKT_PUBLISH_PRIV));
    if(mqtt_pkt_publish_priv == NULL)
    {
        return NULL;
    }

    memset(mqtt_pkt_publish_priv, 0, sizeof(MQTT_PKT_PUBLISH_PRIV));
    mqtt_pkt_publish_priv->get_param = get_param;
    mqtt_pkt_publish_priv->encode = encode;

    uint8_t *ptr = buf;
    int len = 0;

    MQTT_PKT_FIXED_HEADER *mqtt_fixed_header = mqtt_publish_fixed_header_decode(mqtt_pkt_publish_priv, buf, buf_len);
    if(mqtt_fixed_header == NULL)
    {
        return NULL;
    }

    mqtt_pkt_publish_priv->mqtt_fixed_header = mqtt_fixed_header;
    if(mqtt_fixed_header->get_pkt_type(mqtt_fixed_header) != PUBLISH_TYPE)
    {
        return NULL;
    }

    ptr += mqtt_fixed_header->get_pkt_len(mqtt_fixed_header);
    len += mqtt_fixed_header->get_pkt_len(mqtt_fixed_header);

    MQTT_PKT_VAR_HEADER *mqtt_var_header = mqtt_publish_var_header_decode(mqtt_pkt_publish_priv, ptr, buf_len - len, mqtt_pkt_publish_priv->qos);
    if(mqtt_var_header == NULL)
    {
        return NULL;
    }

    mqtt_pkt_publish_priv->mqtt_var_header = mqtt_var_header;
    ptr += mqtt_var_header->get_var_header_len(mqtt_var_header);
    len += mqtt_var_header->get_var_header_len(mqtt_var_header);

    MQTT_PKT_PAYLOAD *mqtt_payload = mqtt_publish_payload_decode(mqtt_pkt_publish_priv, ptr, buf_len - len);
    mqtt_pkt_publish_priv->mqtt_payload = mqtt_payload;

    return (MQTT_PKT_PUBLISH *)mqtt_pkt_publish_priv;
}

MQTT_PKT_PUBLISH *mqtt_pkt_publish_create()
{
    MQTT_PKT_PUBLISH_PRIV *mqtt_pkt_publish_priv = (MQTT_PKT_PUBLISH_PRIV *)malloc(sizeof(MQTT_PKT_PUBLISH_PRIV));
    if(mqtt_pkt_publish_priv == NULL)
    {
        return NULL;
    }

    memset(mqtt_pkt_publish_priv, 0, sizeof(MQTT_PKT_PUBLISH_PRIV));

    mqtt_pkt_publish_priv->get_param = get_param;
    mqtt_pkt_publish_priv->encode = encode;

    return (MQTT_PKT_PUBLISH *)mqtt_pkt_publish_priv;
}

int destroy_publish(MQTT_PKT_PUBLISH *mqtt_pkt_publish)
{
    MQTT_PKT_PUBLISH_PRIV *mqtt_pkt_publish_priv = (MQTT_PKT_PUBLISH_PRIV *)mqtt_pkt_publish;
    if(mqtt_pkt_publish_priv == NULL)
    {
        return -1;
    }

    if(mqtt_pkt_publish_priv->mqtt_fixed_header != NULL)
    {
        destroy_fixed_header(mqtt_pkt_publish_priv->mqtt_fixed_header);
    }

    if(mqtt_pkt_publish_priv->mqtt_var_header != NULL)
    {
        destroy_var_header(mqtt_pkt_publish_priv->mqtt_var_header);
    }

    if(mqtt_pkt_publish_priv->mqtt_payload != NULL)
    {
        destroy_payload(mqtt_pkt_publish_priv->mqtt_payload);
    }

    free(mqtt_pkt_publish_priv);

    return 0;
}

int mqtt_pkt_publish_init(MQTT_PKT_PUBLISH *mqtt_pkt_publish, MQTT_PKT_PUBLISH_PARAM *param)
{
    MQTT_PKT_PUBLISH_PRIV *mqtt_pkt_publish_priv = (MQTT_PKT_PUBLISH_PRIV *)mqtt_pkt_publish;
    if(mqtt_pkt_publish_priv == NULL || param == NULL)
    {
        return -1;
    }

    mqtt_pkt_publish_priv->mqtt_fixed_header = mqtt_fixed_header_create();
    if(mqtt_pkt_publish_priv->mqtt_fixed_header == NULL)
    {
        return -1;
    }

    mqtt_pkt_publish_priv->mqtt_var_header = mqtt_var_header_create();
    if(mqtt_pkt_publish_priv->mqtt_var_header == NULL)
    {
        return -1;
    }

    mqtt_pkt_publish_priv->mqtt_payload = mqtt_payload_create();
    if(mqtt_pkt_publish_priv->mqtt_payload == NULL)
    {
        return -1;
    }

    mqtt_pkt_publish_priv->qos = param->qos;
    mqtt_pkt_publish_priv->retain = param->retain;
    mqtt_pkt_publish_priv->dup = param->dup;
    mqtt_pkt_publish_priv->packet_id = param->packet_id;

    snprintf(mqtt_pkt_publish_priv->topic_name, sizeof(mqtt_pkt_publish_priv->topic_name), "%s", param->topic_name);
    snprintf(mqtt_pkt_publish_priv->message, sizeof(mqtt_pkt_publish_priv->message), "%s", param->message);

    mqtt_pkt_publish_priv->mqtt_fixed_header->set_pkt_type(mqtt_pkt_publish_priv->mqtt_fixed_header, PUBLISH_TYPE);
    int flag = 0;
    flag = (param->dup & 0x1) << 3;
    flag |= (param->qos & 0x3) << 1;
    flag |= param->retain & 0x1;
    mqtt_pkt_publish_priv->mqtt_fixed_header->set_pkt_flag(mqtt_pkt_publish_priv->mqtt_fixed_header, flag);

    int var_header_len = 0;
    uint8_t buf[1024] = {0};
    uint8_t *p = buf;
    int len = 0;
    len = encode_string(p, param->topic_name);
    p += len;
    var_header_len += len;
    int packet_id_len = 0;
    if(param->qos > 0 && param->packet_id >= 0)
    {
        int packet_id_len = encode_int(p, param->packet_id);
        p += packet_id_len;
        var_header_len += packet_id_len;
    }

    uint8_t *var_header = (uint8_t *)malloc(var_header_len);
    memcpy(var_header, buf, var_header_len);
    mqtt_pkt_publish_priv->mqtt_var_header->set_var_header_len(mqtt_pkt_publish_priv->mqtt_var_header, var_header_len);
    mqtt_pkt_publish_priv->mqtt_var_header->set_var_header(mqtt_pkt_publish_priv->mqtt_var_header, var_header);

    int payload_len = 0;

    if (strlen(param->message) > 0)
    {
        memset(buf, 0, sizeof(buf));
        p = buf;
        payload_len = encode_string(p, param->message);
        uint8_t *payload = (uint8_t *)malloc(payload_len);
        memcpy(payload, buf, payload_len);
        mqtt_pkt_publish_priv->mqtt_payload->set_payload_len(mqtt_pkt_publish_priv->mqtt_payload, payload_len);
        mqtt_pkt_publish_priv->mqtt_payload->set_payload(mqtt_pkt_publish_priv->mqtt_payload, payload);
    }
    else
    {
        mqtt_pkt_publish_priv->mqtt_payload->set_payload_len(mqtt_pkt_publish_priv->mqtt_payload, 0);
        mqtt_pkt_publish_priv->mqtt_payload->set_payload(mqtt_pkt_publish_priv->mqtt_payload, NULL);
    }

    mqtt_pkt_publish_priv->mqtt_fixed_header->set_pkt_rem_len(mqtt_pkt_publish_priv->mqtt_fixed_header, var_header_len + payload_len);

    return 0;
}
