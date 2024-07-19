#include "mqtt_connect.h"
#include "mqtt_fixed_header.h"
#include "mqtt_var_header.h"
#include "mqtt_payload.h"
#include "encode.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>


/* connect struct*/
typedef struct MQTT_PKT_CONNECT_PRIV_S
{
    MQTT_PKT_CONNECT_PUBLIC_MEMBER;
    MQTT_PKT_CONNECT_PRIVATE_MEMBER;
}MQTT_PKT_CONNECT_PRIV;




static MQTT_PKT_VAR_HEADER * connect_var_header_decode(uint8_t *buf, int buf_len)
{
    MQTT_PKT_VAR_HEADER *mqtt_var_header = mqtt_var_header_create();
    uint8_t *var_header = malloc(10);
    memcpy(var_header, buf, 10);
    mqtt_var_header->set_var_header(mqtt_var_header, var_header);
    mqtt_var_header->set_var_header_len(mqtt_var_header, 10);
    return mqtt_var_header;
}

static MQTT_PKT_PAYLOAD * connect_payload_decode(uint8_t *buf, int payload_len)
{
    MQTT_PKT_PAYLOAD *mqtt_payload = mqtt_payload_create();
    uint8_t *payload_ptr = buf;
    unsigned char *payload =malloc(payload_len);
    memcpy(payload, payload_ptr, payload_len);
    mqtt_payload->set_payload_len(mqtt_payload, payload_len);
    mqtt_payload->set_payload(mqtt_payload, payload);
    return mqtt_payload;
}

static int construct_connect_var_header(MQTT_PKT_CONNECT *mqtt_pkt_connect, MQTT_CONNECT_PARAM *param)
{
    MQTT_PKT_CONNECT_PRIV *mqtt_pkt_connect_priv = (MQTT_PKT_CONNECT_PRIV *)mqtt_pkt_connect;
    MQTT_PKT_VAR_HEADER *mqtt_var_header = mqtt_pkt_connect_priv->mqtt_var_header;
    uint8_t * var_header = (uint8_t *)malloc(10);

    if (var_header == NULL)
    {
        return -1;
    }
    
    uint8_t *var_header_ptr = var_header;

    int protocol_name_len = encode_string(var_header_ptr, param->protocol_name);
    snprintf(mqtt_pkt_connect_priv->protocol_name, sizeof(mqtt_pkt_connect_priv->protocol_name), "%s", param->protocol_name);
    
    var_header_ptr += protocol_name_len;
    *var_header_ptr = param->protocol_level;
    mqtt_pkt_connect_priv->protocol_level = param->protocol_level;
    
    var_header_ptr++;
    *var_header_ptr = param->connect_flag;
    mqtt_pkt_connect_priv->connect_flag = param->connect_flag;

    var_header_ptr++;
    *var_header_ptr = (param->keep_alive >> 8) & 0xFF;
    var_header_ptr++;
    *var_header_ptr = param->keep_alive & 0xFF;
    mqtt_pkt_connect_priv->keep_alive = param->keep_alive;

    var_header_ptr++;

    mqtt_var_header->set_var_header(mqtt_var_header, var_header);

    mqtt_var_header->set_var_header_len(mqtt_var_header, 10);

    return 0;
}



static int construct_connect_payload(MQTT_PKT_CONNECT *mqtt_pkt_connect, MQTT_CONNECT_PARAM *param)
{
    MQTT_PKT_CONNECT_PRIV *mqtt_pkt_connect_priv = (MQTT_PKT_CONNECT_PRIV *)mqtt_pkt_connect;
    MQTT_PKT_PAYLOAD *mqtt_payload = mqtt_pkt_connect_priv->mqtt_payload;
    int connect_flag = param->connect_flag;

    int client_id_len = 0;
    int will_topic_len = 0;
    int will_message_len = 0;
    int user_name_len = 0;
    int password_len = 0;


    unsigned char client_id[32] = {0};
    unsigned char will_message[128] = {0};
    unsigned char will_topic[32] ={0};
    unsigned char user_name[64] = {0};
    unsigned char password[64] = {0};

    client_id_len = encode_string(client_id, param->client_id);
    snprintf(mqtt_pkt_connect_priv->client_id, sizeof(mqtt_pkt_connect_priv->client_id), "%s", param->client_id);

    if(connect_flag & 0x02)
    {
        will_topic_len = encode_string(will_topic, param->will_topic);
        will_message_len = encode_string(will_message, param->will_message);

        snprintf(mqtt_pkt_connect_priv->will_topic, sizeof(mqtt_pkt_connect_priv->will_topic), "%s", param->will_topic);
        snprintf(mqtt_pkt_connect_priv->will_message, sizeof(mqtt_pkt_connect_priv->will_message), "%s", param->will_message);
    }

    if(connect_flag & 0x80)
    {
        user_name_len = encode_string(user_name, param->user_name);
        snprintf(mqtt_pkt_connect_priv->user_name, sizeof(mqtt_pkt_connect_priv->user_name), "%s", param->user_name);
    }

    if(connect_flag & 0x40)
    {
        password_len = encode_string(password, param->password);
        snprintf(mqtt_pkt_connect_priv->password, sizeof(mqtt_pkt_connect_priv->password), "%s", param->password);
    }

    int payload_len = client_id_len + will_topic_len + will_message_len + user_name_len + password_len;

    unsigned char  *payload = (unsigned char *)malloc(payload_len);
    unsigned char *payload_ptr = payload;

    memcpy(payload_ptr, client_id, client_id_len);
    payload_ptr += client_id_len;

    if(connect_flag & 0x02)
    {
        memcpy(payload_ptr, will_topic, will_topic_len);
        payload_ptr += will_topic_len;
        memcpy(payload_ptr, will_message, will_message_len);
        payload_ptr += will_message_len;
    }

    if(connect_flag & 0x80)
    {
        memcpy(payload_ptr, user_name, user_name_len);
        payload_ptr += user_name_len;
    }

    if(connect_flag & 0x40)
    {
        memcpy(payload_ptr, password, password_len);
        payload_ptr += password_len;
    }


    mqtt_payload->set_payload(mqtt_payload, payload);
    mqtt_payload->set_payload_len(mqtt_payload, payload_len);

    return 0;

}

static int construct_connect_fixed_header(MQTT_PKT_CONNECT *mqtt_pkt_connect)
{
    MQTT_PKT_CONNECT_PRIV *mqtt_pkt_connect_priv = (MQTT_PKT_CONNECT_PRIV *)mqtt_pkt_connect;
    MQTT_PKT_FIXED_HEADER *mqtt_fixed_header = mqtt_pkt_connect_priv->mqtt_fixed_header;
    mqtt_fixed_header->set_pkt_type(mqtt_fixed_header, 1);
    mqtt_fixed_header->set_pkt_flag(mqtt_fixed_header, 0);
    return 0;
}



int mqtt_pkt_connect_init(MQTT_PKT_CONNECT *mqtt_pkt_connect, MQTT_CONNECT_PARAM *param)
{
    MQTT_PKT_CONNECT_PRIV *mqtt_pkt_connect_priv = (MQTT_PKT_CONNECT_PRIV *)mqtt_pkt_connect;
    mqtt_pkt_connect_priv->mqtt_fixed_header = mqtt_fixed_header_create();
    mqtt_pkt_connect_priv->mqtt_var_header = mqtt_var_header_create();
    mqtt_pkt_connect_priv->mqtt_payload = mqtt_payload_create();
    mqtt_pkt_connect_priv->mqtt_fixed_header = mqtt_fixed_header_create();
    mqtt_pkt_connect_priv->mqtt_var_header = mqtt_var_header_create();
    mqtt_pkt_connect_priv->mqtt_payload = mqtt_payload_create();
    construct_connect_fixed_header(mqtt_pkt_connect);
    construct_connect_var_header(mqtt_pkt_connect, param);
    construct_connect_payload(mqtt_pkt_connect, param);

    int rem_len = mqtt_pkt_connect_priv->mqtt_var_header->get_var_header_len(mqtt_pkt_connect_priv->mqtt_var_header) 
                    + mqtt_pkt_connect_priv->mqtt_payload->get_payload_len(mqtt_pkt_connect_priv->mqtt_payload);

    mqtt_pkt_connect_priv->mqtt_fixed_header->set_pkt_rem_len(mqtt_pkt_connect_priv->mqtt_fixed_header, rem_len);

    return 0;

}

static int encode(struct MQTT_PKT_CONNECT_S *mqtt_pkt_connect, uint8_t *buf)
{
    MQTT_PKT_CONNECT_PRIV *mqtt_pkt_connect_priv = (MQTT_PKT_CONNECT_PRIV *)mqtt_pkt_connect;
    MQTT_PKT_FIXED_HEADER *mqtt_fixed_header = mqtt_pkt_connect_priv->mqtt_fixed_header;
    MQTT_PKT_VAR_HEADER *mqtt_var_header = mqtt_pkt_connect_priv->mqtt_var_header;
    MQTT_PKT_PAYLOAD *mqtt_payload = mqtt_pkt_connect_priv->mqtt_payload;
    uint8_t *buf_ptr = buf;
    int pkt_len = 0;
    int var_header_len = 0;
    int payload_len = 0;
    int fixed_header_len = 0;
    int rem_len = 0;

    var_header_len = mqtt_var_header->get_var_header_len(mqtt_var_header);
    payload_len = mqtt_payload->get_payload_len(mqtt_payload);
    rem_len = var_header_len + payload_len;
    mqtt_fixed_header->set_pkt_rem_len(mqtt_fixed_header, rem_len);

    fixed_header_len = mqtt_fixed_header->encode(mqtt_fixed_header, buf_ptr);
    
    
    buf_ptr += fixed_header_len;

    mqtt_var_header->encode(mqtt_var_header, buf_ptr);

    buf_ptr += var_header_len;

    mqtt_payload->encode(mqtt_payload, buf_ptr);

    pkt_len = rem_len + fixed_header_len;

    return pkt_len;
}

static int get_param(struct MQTT_PKT_CONNECT_S *mqtt_pkt_connect, MQTT_CONNECT_PARAM *param)
{
    MQTT_PKT_CONNECT_PRIV *mqtt_pkt_connect_priv = (MQTT_PKT_CONNECT_PRIV *)mqtt_pkt_connect;
    snprintf(param->protocol_name, sizeof(param->protocol_name), "%s", mqtt_pkt_connect_priv->protocol_name);
    param->protocol_level = mqtt_pkt_connect_priv->protocol_level;
    param->connect_flag = mqtt_pkt_connect_priv->connect_flag;
    param->keep_alive = mqtt_pkt_connect_priv->keep_alive;
    snprintf(param->client_id, sizeof(param->client_id), "%s", mqtt_pkt_connect_priv->client_id);
    snprintf(param->will_topic, sizeof(param->will_topic), "%s", mqtt_pkt_connect_priv->will_topic);
    snprintf(param->will_message, sizeof(param->will_message), "%s", mqtt_pkt_connect_priv->will_message);
    snprintf(param->user_name, sizeof(param->user_name), "%s", mqtt_pkt_connect_priv->user_name);
    snprintf(param->password, sizeof(param->password), "%s", mqtt_pkt_connect_priv->password);
    return 0;
}

struct MQTT_PKT_CONNECT_S* mqtt_pkt_connect_decode(uint8_t *buf, int buf_len)
{
    if (buf == NULL || buf_len < 2)
    {
        printf("buf == NULL || buf_len < 2\n");
        return NULL;
    }
    

    MQTT_PKT_CONNECT_PRIV *mqtt_pkt_connect_priv = (MQTT_PKT_CONNECT_PRIV *)malloc(sizeof(MQTT_PKT_CONNECT_PRIV));

    if (mqtt_pkt_connect_priv == NULL)
    {
        printf("malloc failed\n");
        return NULL;
    }

    uint8_t * buf_ptr = buf;
    int buf_ptr_len = buf_len;
    
    MQTT_PKT_FIXED_HEADER *fixed_header = mqtt_fixed_header_decode(buf_ptr, buf_ptr_len);

    if (fixed_header == NULL)
    {
        printf("fixed_header == NULL\n");
        return NULL;
    }

    buf_ptr += fixed_header->get_pkt_len(fixed_header);
    buf_ptr_len -= fixed_header->get_pkt_len(fixed_header);

    MQTT_PKT_VAR_HEADER *var_header = connect_var_header_decode(buf_ptr, buf_ptr_len);

    if (var_header == NULL)
    {
        printf("var_header == NULL\n");
        return NULL;
    }

    buf_ptr += var_header->get_var_header_len(var_header);
    buf_ptr_len -= var_header->get_var_header_len(var_header);
    
    MQTT_PKT_PAYLOAD *payload = connect_payload_decode(buf_ptr, buf_ptr_len);

    if (payload == NULL)
    {
        printf("payload == NULL\n");
        return NULL;
    }


    /*init methods*/
    mqtt_pkt_connect_priv->encode = encode;
    mqtt_pkt_connect_priv->get_param = get_param;
    
    int protocol_name_len = decode_string(var_header->get_var_header(var_header), mqtt_pkt_connect_priv->protocol_name);
    mqtt_pkt_connect_priv->protocol_level = var_header->get_var_header(var_header)[protocol_name_len];
    mqtt_pkt_connect_priv->connect_flag = var_header->get_var_header(var_header)[protocol_name_len+1];
    mqtt_pkt_connect_priv->keep_alive = (var_header->get_var_header(var_header)[protocol_name_len+2] << 8) | var_header->get_var_header(var_header)[protocol_name_len+3];
    int client_id_len = decode_string(payload->get_payload(payload), mqtt_pkt_connect_priv->client_id);
    int will_topic_len = 0;
    int will_message_len = 0;
    int user_name_len = 0;
    int password_len = 0;
    if(mqtt_pkt_connect_priv->connect_flag & 0x02)
    {
        will_topic_len = decode_string(payload->get_payload(payload)+client_id_len, mqtt_pkt_connect_priv->will_topic);
        will_message_len = decode_string(payload->get_payload(payload)+client_id_len+will_topic_len, mqtt_pkt_connect_priv->will_message);
    }
    if(mqtt_pkt_connect_priv->connect_flag & 0x80)
    {
        user_name_len = decode_string(payload->get_payload(payload)+client_id_len+will_topic_len+will_message_len, mqtt_pkt_connect_priv->user_name);
    }
    if(mqtt_pkt_connect_priv->connect_flag & 0x40)
    {
        password_len = decode_string(payload->get_payload(payload)+client_id_len+will_topic_len+will_message_len+user_name_len, mqtt_pkt_connect_priv->password);
    }
    mqtt_pkt_connect_priv->mqtt_fixed_header = fixed_header;
    mqtt_pkt_connect_priv->mqtt_var_header = var_header;
    mqtt_pkt_connect_priv->mqtt_payload = payload;
    return (MQTT_PKT_CONNECT *)mqtt_pkt_connect_priv;
}

MQTT_PKT_CONNECT* mqtt_pkt_connect_create()
{
    MQTT_PKT_CONNECT_PRIV *mqtt_pkt_connect_priv = (MQTT_PKT_CONNECT_PRIV *)malloc(sizeof(MQTT_PKT_CONNECT_PRIV));
    mqtt_pkt_connect_priv->encode = encode;
    mqtt_pkt_connect_priv->get_param = get_param;
    return (MQTT_PKT_CONNECT *)mqtt_pkt_connect_priv;
}

int destroy_connect(MQTT_PKT_CONNECT *mqtt_pkt_connect)
{
    MQTT_PKT_CONNECT_PRIV *mqtt_pkt_connect_priv = (MQTT_PKT_CONNECT_PRIV *)mqtt_pkt_connect;
    destroy_fixed_header(mqtt_pkt_connect_priv->mqtt_fixed_header);
    destroy_var_header(mqtt_pkt_connect_priv->mqtt_var_header);
    destroy_payload(mqtt_pkt_connect_priv->mqtt_payload);
    free(mqtt_pkt_connect_priv);
    return 0;
}


