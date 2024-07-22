#include "mqtt_subscribe.h"
#include "mqtt_fixed_header.h"
#include "mqtt_var_header.h"
#include "mqtt_payload.h"
#include "encode.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define SUBSCRIBE_TYPE 8
#define SUBSCRIBE_VAR_HEADER_LEN 2

typedef struct MQTT_PKT_SUBSCRIBE_PRIV_S
{
    MQTT_PKT_SUBSCRIBE_PUBLIC_MEMBER;
    MQTT_PKT_SUBSCRIBE_PRIVATE_MEMBER;
}MQTT_PKT_SUBSCRIBE_PRIV;

static int get_pkt_id(MQTT_PKT_SUBSCRIBE *mqtt_pkt_subscribe)
{
    MQTT_PKT_SUBSCRIBE_PRIV *mqtt_pkt_subscribe_priv = (MQTT_PKT_SUBSCRIBE_PRIV *)mqtt_pkt_subscribe;
    return mqtt_pkt_subscribe_priv->pkt_id;
}

static int set_pkt_id(MQTT_PKT_SUBSCRIBE *mqtt_pkt_subscribe, int pkt_id)
{
    MQTT_PKT_SUBSCRIBE_PRIV *mqtt_pkt_subscribe_priv = (MQTT_PKT_SUBSCRIBE_PRIV *)mqtt_pkt_subscribe;
    mqtt_pkt_subscribe_priv->pkt_id = pkt_id;
    return 0;
}

static int update_payload(MQTT_PKT_SUBSCRIBE *mqtt_pkt_subscribe)
{
    MQTT_PKT_SUBSCRIBE_PRIV *mqtt_pkt_subscribe_priv = (MQTT_PKT_SUBSCRIBE_PRIV *)mqtt_pkt_subscribe;
    if (mqtt_pkt_subscribe_priv == NULL)
    {
        return -1;
    }

    if (mqtt_pkt_subscribe_priv->mqtt_payload == NULL)
    {
        return -1;
    }

    int payload_len = 0;
    TOPIC_QOS *tmp = mqtt_pkt_subscribe_priv->topic_qos;
    int topic_count = mqtt_pkt_subscribe_priv->topic_count;

    while (tmp != NULL)
    {
        payload_len += 2 + strlen(tmp->topic) + 1;
        tmp = tmp->next;
    }

    mqtt_pkt_subscribe_priv->mqtt_payload->set_payload_len(mqtt_pkt_subscribe_priv->mqtt_payload, payload_len);

    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (payload == NULL)
    {
        return -1;
    }

    tmp = mqtt_pkt_subscribe_priv->topic_qos;

    uint8_t* ptr = payload;
    int temp_len = 0;
    while (tmp != NULL)
    {
        temp_len = encode_string(ptr, tmp->topic);
        ptr += temp_len;
        ptr[0] = tmp->qos;
        ptr += 1;
        tmp = tmp->next;
    }

    mqtt_pkt_subscribe_priv->mqtt_payload->set_payload(mqtt_pkt_subscribe_priv->mqtt_payload, payload);
    mqtt_pkt_subscribe_priv->mqtt_payload->set_payload_len(mqtt_pkt_subscribe_priv->mqtt_payload, payload_len);

    int rem_len = payload_len + SUBSCRIBE_VAR_HEADER_LEN;
    mqtt_pkt_subscribe_priv->mqtt_fixed_header->set_pkt_rem_len(mqtt_pkt_subscribe_priv->mqtt_fixed_header, rem_len);
    
    return 0;
}

static TOPIC_QOS *get_topic(MQTT_PKT_SUBSCRIBE *mqtt_pkt_subscribe)
{
    MQTT_PKT_SUBSCRIBE_PRIV *mqtt_pkt_subscribe_priv = (MQTT_PKT_SUBSCRIBE_PRIV *)mqtt_pkt_subscribe;
    if (mqtt_pkt_subscribe_priv == NULL)
    {
        return NULL;
    }

    if (mqtt_pkt_subscribe_priv->mqtt_payload == NULL)
    {
        return NULL;
    }  

    // if (topic_qos == NULL)
    // {
    //     return -1;
    // }

    if (mqtt_pkt_subscribe_priv->topic_qos == NULL)
    {
        printf("topic_qos is NULL\n");
        return NULL;
    }

    TOPIC_QOS* tmp = mqtt_pkt_subscribe_priv->topic_qos;

    return mqtt_pkt_subscribe_priv->topic_qos;

}


static int add_topic(MQTT_PKT_SUBSCRIBE *mqtt_pkt_subscribe, char *topic, int qos)
{
    MQTT_PKT_SUBSCRIBE_PRIV *mqtt_pkt_subscribe_priv = (MQTT_PKT_SUBSCRIBE_PRIV *)mqtt_pkt_subscribe;
    if (mqtt_pkt_subscribe_priv == NULL)
    {
        return -1;
    }

    if (mqtt_pkt_subscribe_priv->mqtt_payload == NULL)
    {
        return -1;
    }

    TOPIC_QOS *topic_qos = (TOPIC_QOS *)malloc(sizeof(TOPIC_QOS));
    if (topic_qos == NULL)
    {
        return -1;
    }

    topic_qos->qos = qos;
    snprintf(topic_qos->topic, sizeof(topic_qos->topic), "%s", topic);
    topic_qos->next = NULL;

    if (mqtt_pkt_subscribe_priv->topic_qos == NULL)
    {
        mqtt_pkt_subscribe_priv->topic_qos = topic_qos;
    }
    else
    {
        TOPIC_QOS *tmp = mqtt_pkt_subscribe_priv->topic_qos;
        while (tmp->next != NULL)
        {
            tmp = tmp->next;
        }
        tmp->next = topic_qos;
    }

    mqtt_pkt_subscribe_priv->topic_count++;

    return 0;
}

static int free_topic_qos(TOPIC_QOS *topic_qos)
{
    if (topic_qos == NULL)
    {
        return 0;
    }

    TOPIC_QOS *tmp = topic_qos;
    while (tmp != NULL)
    {
        TOPIC_QOS *next = tmp->next;
        free(tmp);
        tmp = next;
    }

    return 0;
}

static int encode(MQTT_PKT_SUBSCRIBE *mqtt_pkt_subscribe, uint8_t* buf)
{
    MQTT_PKT_SUBSCRIBE_PRIV *mqtt_pkt_subscribe_priv = (MQTT_PKT_SUBSCRIBE_PRIV *)mqtt_pkt_subscribe;
    if (mqtt_pkt_subscribe_priv == NULL)
    {
        return -1;
    }

    if (mqtt_pkt_subscribe_priv->mqtt_fixed_header == NULL || mqtt_pkt_subscribe_priv->mqtt_var_header == NULL || mqtt_pkt_subscribe_priv->mqtt_payload == NULL)
    {
        return -1;
    }

    update_payload(mqtt_pkt_subscribe);

    int fixed_header_len = mqtt_pkt_subscribe_priv->mqtt_fixed_header->encode(mqtt_pkt_subscribe_priv->mqtt_fixed_header, buf);

    int var_header_len = encode_int(buf+fixed_header_len, mqtt_pkt_subscribe_priv->pkt_id);

    int payload_len = mqtt_pkt_subscribe_priv->mqtt_payload->get_payload_len(mqtt_pkt_subscribe_priv->mqtt_payload);

    uint8_t *payload = mqtt_pkt_subscribe_priv->mqtt_payload->get_payload(mqtt_pkt_subscribe_priv->mqtt_payload);

    memcpy(buf+fixed_header_len+var_header_len, payload, payload_len);

    return fixed_header_len+var_header_len+payload_len;
}

struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe_create(int packet_id)
{
    struct MQTT_PKT_SUBSCRIBE_PRIV_S *mqtt_pkt_subscribe_priv = (struct MQTT_PKT_SUBSCRIBE_PRIV_S *)malloc(sizeof(struct MQTT_PKT_SUBSCRIBE_PRIV_S));
    if (mqtt_pkt_subscribe_priv == NULL)
    {
        return NULL;
    }

    mqtt_pkt_subscribe_priv->get_pkt_id = get_pkt_id;
    mqtt_pkt_subscribe_priv->set_pkt_id = set_pkt_id;
    mqtt_pkt_subscribe_priv->get_topic = get_topic;
    mqtt_pkt_subscribe_priv->add_topic = add_topic;
    mqtt_pkt_subscribe_priv->encode = encode;

    mqtt_pkt_subscribe_priv->pkt_id = packet_id;

    mqtt_pkt_subscribe_priv->mqtt_fixed_header = mqtt_fixed_header_create();
    if (mqtt_pkt_subscribe_priv->mqtt_fixed_header == NULL)
    {
        free(mqtt_pkt_subscribe_priv);
        return NULL;
    }

    mqtt_pkt_subscribe_priv->mqtt_fixed_header->set_pkt_type(mqtt_pkt_subscribe_priv->mqtt_fixed_header, SUBSCRIBE_TYPE);
    mqtt_pkt_subscribe_priv->mqtt_fixed_header->set_pkt_flag(mqtt_pkt_subscribe_priv->mqtt_fixed_header, 2);

    mqtt_pkt_subscribe_priv->mqtt_var_header = mqtt_var_header_create();
    if (mqtt_pkt_subscribe_priv->mqtt_var_header == NULL)
    {
        free(mqtt_pkt_subscribe_priv);
        return NULL;
    }    

    mqtt_pkt_subscribe_priv->mqtt_payload = mqtt_payload_create();
    if (mqtt_pkt_subscribe_priv->mqtt_payload == NULL)
    {
        free(mqtt_pkt_subscribe_priv);
        return NULL;
    }

    mqtt_pkt_subscribe_priv->topic_count = 0;
    mqtt_pkt_subscribe_priv->topic_qos = NULL;

    return (struct MQTT_PKT_SUBSCRIBE_S *)mqtt_pkt_subscribe_priv;
}

int destroy_subscribe(struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe)
{
    MQTT_PKT_SUBSCRIBE_PRIV *mqtt_pkt_subscribe_priv = (MQTT_PKT_SUBSCRIBE_PRIV *)mqtt_pkt_subscribe;
    if (mqtt_pkt_subscribe_priv == NULL)
    {
        return -1;
    }

    if (mqtt_pkt_subscribe_priv->mqtt_fixed_header != NULL)
    {
        destroy_fixed_header(mqtt_pkt_subscribe_priv->mqtt_fixed_header);
    }

    if (mqtt_pkt_subscribe_priv->mqtt_var_header != NULL)
    {
        destroy_var_header(mqtt_pkt_subscribe_priv->mqtt_var_header);
    }

    if (mqtt_pkt_subscribe_priv->mqtt_payload != NULL)
    {
        destroy_payload(mqtt_pkt_subscribe_priv->mqtt_payload);
    }

    free_topic_qos(mqtt_pkt_subscribe_priv->topic_qos);

    free(mqtt_pkt_subscribe_priv);

    return 0;
}

int mqtt_pkt_subscribe_init(MQTT_PKT_SUBSCRIBE *mqtt_pkt_subscribe, TOPIC_QOS *topics)
{
    MQTT_PKT_SUBSCRIBE_PRIV *mqtt_pkt_subscribe_priv = (MQTT_PKT_SUBSCRIBE_PRIV *)mqtt_pkt_subscribe;
    if (mqtt_pkt_subscribe_priv == NULL)
    {
        return -1;
    }

    mqtt_pkt_subscribe_priv->topic_count = 0;
    TOPIC_QOS *tps = NULL;
    mqtt_pkt_subscribe_priv->topic_qos = tps;

    TOPIC_QOS *tmp = topics;
    while (tmp != NULL)
    {
        add_topic(mqtt_pkt_subscribe, tmp->topic, tmp->qos);
        tmp = tmp->next;
    }

    return 0;
}

static int decode_tpoic_qos(uint8_t *buf, int len, TOPIC_QOS **topic_qos)
{
    if (buf == NULL || len < 3)
    {
        return -1;
    }

    int  topic_count = 0;
    uint8_t * ptr = buf;
    TOPIC_QOS* tmp_topic_qos = NULL;
    TOPIC_QOS* tmp = NULL;

    while (ptr - buf < len)
    {
        TOPIC_QOS *topic = (TOPIC_QOS *)malloc(sizeof(TOPIC_QOS));
        topic->next = NULL;
        if (topic == NULL)
        {
            return -1;
        }

        int topic_len = decode_string(ptr, topic->topic);
        ptr += topic_len;
        topic->qos = ptr[0];
        ptr += 1;

        if (tmp_topic_qos == NULL)
        {
            tmp_topic_qos = topic;
            tmp = tmp_topic_qos;
        }
        else
        {
            tmp->next = topic;
            tmp = tmp->next;
        }

        topic_count++;
    }

    *topic_qos = tmp_topic_qos;  // 将头部指针赋值给传入的指针的指针

    return topic_count;
}



struct MQTT_PKT_SUBSCRIBE_S *mqtt_pkt_subscribe_decode(uint8_t *buf, int len)
{
    if (buf == NULL || len < 2)
    {
        return NULL;
    }

    /*init*/    
    MQTT_PKT_SUBSCRIBE_PRIV *mqtt_pkt_subscribe_priv = (MQTT_PKT_SUBSCRIBE_PRIV *)malloc(sizeof(MQTT_PKT_SUBSCRIBE_PRIV));
    mqtt_pkt_subscribe_priv->get_pkt_id = get_pkt_id;
    mqtt_pkt_subscribe_priv->set_pkt_id = set_pkt_id;
    mqtt_pkt_subscribe_priv->get_topic = get_topic;
    mqtt_pkt_subscribe_priv->add_topic = add_topic;
    mqtt_pkt_subscribe_priv->encode = encode;

    /*decode*/
    mqtt_pkt_subscribe_priv->pkt_id = (buf[0] << 8) | buf[1];
    
    mqtt_pkt_subscribe_priv->mqtt_fixed_header = mqtt_fixed_header_decode(buf, len);
    if (mqtt_pkt_subscribe_priv->mqtt_fixed_header == NULL)
    {
        free(mqtt_pkt_subscribe_priv);
        return NULL;
    }

    int rem_len = mqtt_pkt_subscribe_priv->mqtt_fixed_header->get_pkt_rem_len(mqtt_pkt_subscribe_priv->mqtt_fixed_header);
    int fixed_header_len = mqtt_pkt_subscribe_priv->mqtt_fixed_header->get_pkt_len(mqtt_pkt_subscribe_priv->mqtt_fixed_header);

    mqtt_pkt_subscribe_priv->mqtt_var_header = mqtt_var_header_create();
    mqtt_pkt_subscribe_priv->mqtt_var_header->set_var_header_len(mqtt_pkt_subscribe_priv->mqtt_var_header, 2);
    uint8_t *var_header = (uint8_t *)malloc(2);
    if (var_header == NULL)
    {
        destroy_fixed_header(mqtt_pkt_subscribe_priv->mqtt_fixed_header);
        free(mqtt_pkt_subscribe_priv);
        return NULL;
    }
    var_header[0] = buf[fixed_header_len];
    var_header[1] = buf[fixed_header_len+1];

    mqtt_pkt_subscribe_priv->mqtt_var_header->set_var_header(mqtt_pkt_subscribe_priv->mqtt_var_header, var_header);

    mqtt_pkt_subscribe_priv->mqtt_payload = mqtt_payload_create();
    if (mqtt_pkt_subscribe_priv->mqtt_payload == NULL)
    {
        destroy_fixed_header(mqtt_pkt_subscribe_priv->mqtt_fixed_header);
        destroy_var_header(mqtt_pkt_subscribe_priv->mqtt_var_header);
        free(mqtt_pkt_subscribe_priv);
        return NULL;
    }

    int payload_len = rem_len - SUBSCRIBE_VAR_HEADER_LEN;
    uint8_t *payload = (uint8_t *)malloc(payload_len);
    if (payload == NULL)
    {
        destroy_fixed_header(mqtt_pkt_subscribe_priv->mqtt_fixed_header);
        destroy_var_header(mqtt_pkt_subscribe_priv->mqtt_var_header);
        destroy_payload(mqtt_pkt_subscribe_priv->mqtt_payload);
        free(mqtt_pkt_subscribe_priv);
        return NULL;
    }

    memcpy(payload, buf+fixed_header_len+2, payload_len);

    mqtt_pkt_subscribe_priv->mqtt_payload->set_payload(mqtt_pkt_subscribe_priv->mqtt_payload, payload);

    mqtt_pkt_subscribe_priv->topic_count = decode_tpoic_qos(payload, payload_len, &mqtt_pkt_subscribe_priv->topic_qos);

    TOPIC_QOS *tmp = mqtt_pkt_subscribe_priv->topic_qos;

    return (struct MQTT_PKT_SUBSCRIBE_S *)mqtt_pkt_subscribe_priv;

}
