#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "mqtt_pkt.h"
#include "encode.h"
#include "mqtt_connect.h"
#include "mqtt_connack.h"
#include "mqtt_publish.h"
#include "mqtt_puback.h"
#include "mqtt_pubrec.h"
#include "mqtt_pubrel.h"
#include "mqtt_pubcomp.h"
#include "mqtt_subscribe.h"

void test_mqtt_connect_packet_encode(uint8_t *encoded_buf, int* buf_len) {
    // Create a test packet with specific values
    MQTT_PKT_CONNECT *mqtt_pkt_connect = mqtt_pkt_connect_create();
    MQTT_CONNECT_PARAM param = {
        .protocol_name = "MQTT",
        .protocol_level = 4,
        .connect_flag = 0x02|0x80|0x40,
        .keep_alive = 60,
        .client_id = "test_client",
        .will_topic = "test_topic",
        .will_message = "test_message",
        .user_name = "test_user",
        .password = "test_password"
    };
    mqtt_pkt_connect_init(mqtt_pkt_connect, &param);

    // Encode the packet
    uint8_t buf[MQTT_PKT_MAX_SIZE] = {0};
    int connect_len = mqtt_pkt_connect->encode(mqtt_pkt_connect, buf);


    uint8_t expected_buf[1024] = {0};

    // Fixed header
    uint8_t *p = expected_buf;

    // Fixed header
    int len = 0;
    int expected_len = 0;

    expected_buf[0] = 0x10;
    expected_buf[1] = 0;

    expected_len += 2;
    p+=2;

    len = encode_string(p, param.protocol_name);
    p += len;
    expected_len += len;

    expected_buf[expected_len] = param.protocol_level;
    expected_len += 1;
    p += 1;

    expected_buf[expected_len] = param.connect_flag;
    expected_len += 1;
    p += 1;

    len = encode_int(p, param.keep_alive);
    p += len;
    expected_len += len;

    // payload
    len = encode_string(p, param.client_id);
    p += len;
    expected_len += len;
    len = encode_string(p, param.will_topic);
    p += len;
    expected_len += len;
    len = encode_string(p, param.will_message);
    p += len;
    expected_len += len;
    len = encode_string(p, param.user_name);
    p += len;
    expected_len += len;
    len = encode_string(p, param.password);
    p += len;
    expected_len += len;

    expected_buf[1] = expected_len - 2;

    // Compare the encoded packet with the expected packet
    if (connect_len == expected_len && memcmp(buf, expected_buf, connect_len) == 0) {
        printf("test_mqtt_connect_packet_encode: Passed\n");
        *buf_len = connect_len;
        memcpy(encoded_buf, buf, connect_len);
    } else {
        printf("test_mqtt_connect_packet_encode: Failed\n");
    }

    // Free the test packet
    destroy_connect(mqtt_pkt_connect);

    printf("destroy_connect_encoded\n");
    return;
}

int test_mqtt_connect_packet_decode(uint8_t * buf, int len)
{
    MQTT_PKT_CONNECT* mqtt_pkt_connect_decoded = mqtt_pkt_connect_decode(buf, len);
    if (mqtt_pkt_connect_decoded == NULL)
    {
        printf("test_mqtt_connect_packet_decode: Failed\n");
        return -1;
    }

    MQTT_CONNECT_PARAM param = {0};
    mqtt_pkt_connect_decoded->get_param(mqtt_pkt_connect_decoded, &param);
    if (strcmp(param.protocol_name, "MQTT") == 0 &&
        param.protocol_level == 4 &&
        param.connect_flag == (0x02|0x80|0x40) &&
        param.keep_alive == 60 &&
        strcmp(param.client_id, "test_client") == 0 &&
        strcmp(param.will_topic, "test_topic") == 0 &&
        strcmp(param.will_message, "test_message") == 0 &&
        strcmp(param.user_name, "test_user") == 0 &&
        strcmp(param.password, "test_password") == 0)
    {
        printf("test_mqtt_connect_packet_decode: Passed\n");
    }
    else
    {
        printf("test_mqtt_connect_packet_decode: Failed\n");
    }

    destroy_connect(mqtt_pkt_connect_decoded);
    printf("destroy_connect_decoded\n");
    return 0;

}

int test_mqtt_connact_packet_encode(uint8_t *encoded_buf, int* buf_len) {
    // Create a test packet with specific values
    MQTT_PKT_CONNACK *mqtt_pkt_connack = mqtt_pkt_connack_create();
    mqtt_pkt_connack_init(mqtt_pkt_connack, 0, 0);

    // Encode the packet
    uint8_t buf[MQTT_PKT_MAX_SIZE] = {0};
    int connack_len = mqtt_pkt_connack->encode(mqtt_pkt_connack, buf);

    uint8_t expected_buf[1024] = {0};

    // Fixed header
    uint8_t *p = expected_buf;

    // Fixed header
    int len = 0;
    int expected_len = 0;

    p[0] = 0x20;
    p[1] = 0;

    expected_len += 2;
    p+=2;
    int rem_len = 0;

    p[0] = 0;
    expected_len += 1;
    rem_len += 1;

    p[1] = 0;
    expected_len += 1;
    rem_len += 1;

    int rem_len_len = encode_rem_len(rem_len, expected_buf+1);


    // for(int i = 0; i < connack_len; i++)
    // {
    //     printf("buf[%d] = 0x%x ", i, buf[i]);
    // }
    // printf("\n");

    // for(int i = 0; i < expected_len; i++)
    // {
    //     printf("expected_buf[%d] = 0x%x ", i, expected_buf[i]);
    // }
    // printf("\n");

    // Compare the encoded packet with the expected packet
    if (connack_len == expected_len && memcmp(buf, expected_buf, connack_len) == 0) {
        printf("test_mqtt_connack_packet_encode: Passed\n");
        *buf_len = connack_len;
        memcpy(encoded_buf, buf, connack_len);
    } else {
        printf("test_mqtt_connack_packet_encode: Failed\n");
    }

    // Free the test packet
    destroy_connack(mqtt_pkt_connack);

    printf("destroy_connack_encoded\n");
    return 0;
}


int test_mqtt_connack_packet_decode(uint8_t * buf, int len)
{
    MQTT_PKT_CONNACK* mqtt_pkt_connack_decoded = mqtt_pkt_connack_decode(buf, len);
    if (mqtt_pkt_connack_decoded == NULL)
    {
        printf("test_mqtt_connack_packet_decode: Failed\n");
        return -1;
    }

    if (mqtt_pkt_connack_decoded->get_session_present(mqtt_pkt_connack_decoded) == 0 &&
        mqtt_pkt_connack_decoded->get_return_code(mqtt_pkt_connack_decoded) == 0 )
    {
        printf("test_mqtt_connack_packet_decode: Passed\n");
    }
    else
    {
        printf("test_mqtt_connack_packet_decode: Failed\n");
    }

    destroy_connack(mqtt_pkt_connack_decoded);
    printf("destroy_connack_decoded\n");
    return 0;

}

int test_mqtt_publish_packet_encode(uint8_t *encoded_buf, int* buf_len) {
    // Create a test packet with specific values
    MQTT_PKT_PUBLISH *mqtt_pkt_publish = mqtt_pkt_publish_create();
    MQTT_PKT_PUBLISH_PARAM param = {
        .dup = 0,
        .qos = 1,
        .retain = 0,
        .topic_name = "test_topic",
        .packet_id = 1,
        .message = "test_payload"
    };
    mqtt_pkt_publish_init(mqtt_pkt_publish, &param);

    // Encode the packet
    uint8_t buf[MQTT_PKT_MAX_SIZE] = {0};
    int publish_len = mqtt_pkt_publish->encode(mqtt_pkt_publish, buf);

    // for (int i = 0; i < publish_len; i++)
    // {
    //     printf("buf[%d] = 0x%x ", i, buf[i]);
    // }
    // printf("\n");
    

    uint8_t expected_buf[1024] = {0};

    // Fixed header
    uint8_t *p = expected_buf;

    uint8_t *var_header = NULL;
    int var_header_len = 0;

    int topic_len = encode_string(p, param.topic_name);
    if (param.qos > 0)
    {
        var_header = (uint8_t *)malloc(topic_len + 2);
        var_header_len = topic_len + 2;
        encode_int(p + topic_len, param.packet_id);
        memcpy(var_header, p, topic_len + 2);
    }
    else
    {
        var_header = (uint8_t *)malloc(topic_len);
        var_header_len = topic_len;
        memcpy(var_header, p, topic_len);
    }

    memset(expected_buf, 0, sizeof(expected_buf));

    //payload
    uint8_t *paylaod = NULL;
    int payload_len = 0;
    if (strlen(param.message) > 0)
    {
        payload_len = encode_string(p, param.message);
        paylaod = (uint8_t *)malloc(payload_len);
        memcpy(paylaod, p, payload_len);
    }

    // Fixed header
    memset(p, 0, 2);
    int type = 0x30;
    int flag = 0;
    flag |= param.dup << 3;
    flag |= param.qos << 1;
    flag |= param.retain;

    p[0] = type | flag;
    int rem_len = var_header_len + payload_len;
    int rem_len_len = encode_rem_len(rem_len, p + 1);

    memcpy(p + 1 + rem_len_len, var_header, var_header_len);

    if (paylaod != NULL)
    {
        memcpy(p + 1 + rem_len_len + var_header_len, paylaod, payload_len);
    }
    int expected_buf_len = 1 + rem_len_len + var_header_len + payload_len;

    // for (int i = 0; i < expected_buf_len; i++)
    // {
    //     printf("expected_buf[%d] = 0x%x ", i, expected_buf[i]);
    // }
    // printf("\n");

    // Compare the encoded packet with the expected packet
    if (publish_len == 1 + rem_len_len + var_header_len + payload_len && memcmp(buf, expected_buf, publish_len) == 0) {
        printf("test_mqtt_publish_packet_encode: Passed\n");
        *buf_len = publish_len;
        memcpy(encoded_buf, buf, publish_len);
    } else {
        printf("test_mqtt_publish_packet_encode: Failed\n");
    }

    // Free the test packet
    destroy_publish(mqtt_pkt_publish);
    free(var_header);
    free(paylaod);
}

int test_mqtt_publish_packet_decode(uint8_t * buf, int len)
{
    MQTT_PKT_PUBLISH* mqtt_pkt_publish_decoded = mqtt_pkt_publish_decode(buf, len);
    if (mqtt_pkt_publish_decoded == NULL)
    {
        printf("test_mqtt_publish_packet_decode: Failed\n");
        return -1;
    }

    MQTT_PKT_PUBLISH_PARAM param = {0};
    mqtt_pkt_publish_decoded->get_param(mqtt_pkt_publish_decoded, &param);

    if (param.dup == 0 &&
        param.qos == 1 &&
        param.retain == 0 &&
        strcmp(param.topic_name, "test_topic") == 0 &&
        param.packet_id == 1 &&
        strcmp(param.message, "test_payload") == 0)
    {
        printf("test_mqtt_publish_packet_decode: Passed\n");
    }
    else
    {
        printf("test_mqtt_publish_packet_decode: Failed\n");
    }

    destroy_publish(mqtt_pkt_publish_decoded);
    printf("destroy_publish_decoded\n");
    return 0;

}

int test_mqtt_puback_packet_encode(uint8_t *encoded_buf, int* buf_len) {
    // Create a test packet with specific values
    MQTT_PKT_PUBACK *mqtt_pkt_puback = mqtt_pkt_puback_create();
    mqtt_pkt_puback_init(mqtt_pkt_puback, 1);

    // Encode the packet
    uint8_t buf[MQTT_PKT_MAX_SIZE] = {0};
    int puback_len = mqtt_pkt_puback->encode(mqtt_pkt_puback, buf);

    for (int i = 0; i < puback_len; i++)
    {
        printf("buf[%d] = 0x%x ", i, buf[i]);
    }
    printf("\n");

    uint8_t expected_buf[1024] = {0};

    // Fixed header
    uint8_t *p = expected_buf;

    // Fixed header
    int len = 0;
    int expected_len = 0;

    p[0] = 0x40;
    p[1] = 0;

    expected_len += 2;
    p+=2;
    int rem_len = 0;

    int var_header_len = encode_int(p, 1);
    rem_len += var_header_len;

    int rem_len_len = encode_rem_len(rem_len, expected_buf+1);
    expected_len = 1 + rem_len_len + var_header_len;

    for (int i = 0; i < expected_len; i++)
    {
        printf("expected_buf[%d] = 0x%x ", i, expected_buf[i]);
    }
    printf("\n");
    printf("puback_len = %d\n", puback_len);
    printf("expected_len = %d\n", expected_len);
    // Compare the encoded packet with the expected packet
    if (puback_len == expected_len && memcmp(buf, expected_buf, puback_len) == 0) {
        printf("test_mqtt_puback_packet_encode: Passed\n");
        *buf_len = puback_len;
        memcpy(encoded_buf, buf, puback_len);
    } else {
        printf("test_mqtt_puback_packet_encode: Failed\n");
    }

    // Free the test packet
    destroy_puback(mqtt_pkt_puback);

    printf("destroy_puback_encoded\n");
    return 0;
}

int test_mqtt_puback_packet_decode(uint8_t * buf, int len)
{
    MQTT_PKT_PUBACK* mqtt_pkt_puback_decoded = mqtt_pkt_puback_decode(buf, len);
    if (mqtt_pkt_puback_decoded == NULL)
    {
        printf("test_mqtt_puback_packet_decode: Failed\n");
        return -1;
    }

    if (mqtt_pkt_puback_decoded->get_pkt_id(mqtt_pkt_puback_decoded) == 1)
    {
        printf("test_mqtt_puback_packet_decode: Passed\n");
    }
    else
    {
        printf("test_mqtt_puback_packet_decode: Failed\n");
    }

    destroy_puback(mqtt_pkt_puback_decoded);
    printf("destroy_puback_decoded\n");
    return 0;

}


int test_mqtt_pubrec_packet_encode(uint8_t *encoded_buf, int* buf_len) {
    int packet_id = 3;
    // Create a test packet with specific values
    MQTT_PKT_PUBREC *mqtt_pkt_pubrec = mqtt_pkt_pubrec_create();
    mqtt_pkt_pubrec_init(mqtt_pkt_pubrec, packet_id);

    // Encode the packet
    uint8_t buf[MQTT_PKT_MAX_SIZE] = {0};
    int pubrec_len = mqtt_pkt_pubrec->encode(mqtt_pkt_pubrec, buf);

    // for (int i = 0; i < pubrec_len; i++)
    // {
    //     printf("buf[%d] = 0x%x ", i, buf[i]);
    // }
    // printf("\n");

    uint8_t expected_buf[1024] = {0};

    // Fixed header
    uint8_t *p = expected_buf;

    // Fixed header
    int len = 0;
    int expected_len = 0;

    p[0] = 0x50;
    p[1] = 0;

    expected_len += 2;
    p+=2;
    int rem_len = 0;

    int var_header_len = encode_int(p, packet_id);
    rem_len += var_header_len;

    int rem_len_len = encode_rem_len(rem_len, expected_buf+1);
    expected_len = 1 + rem_len_len + var_header_len;

    // for (int i = 0; i < expected_len; i++)
    // {
    //     printf("expected_buf[%d] = 0x%x ", i, expected_buf[i]);
    // }
    // printf("\n");
    // printf("pubrec_len = %d\n", pubrec_len);
    // printf("expected_len = %d\n", expected_len);

    // Compare the encoded packet with the expected packet
    if (pubrec_len == expected_len && memcmp(buf, expected_buf, pubrec_len) == 0) {
        printf("test_mqtt_pubrec_packet_encode: Passed\n");
        *buf_len = pubrec_len;
        memcpy(encoded_buf, buf, pubrec_len);
    } else {
        printf("test_mqtt_pubrec_packet_encode: Failed\n");
    }

    // Free the test packet
    destroy_pubrec(mqtt_pkt_pubrec);

    printf("destroy_pubrec_encoded\n");
    return 0;
}

int test_mqtt_pubrec_packet_decode(uint8_t * buf, int len)
{
    MQTT_PKT_PUBREC* mqtt_pkt_pubrec_decoded = mqtt_pkt_pubrec_decode(buf, len);
    if (mqtt_pkt_pubrec_decoded == NULL)
    {
        printf("test_mqtt_pubrec_packet_decode: Failed\n");
        return -1;
    }

    if (mqtt_pkt_pubrec_decoded->get_pkt_id(mqtt_pkt_pubrec_decoded) == 3)
    {
        printf("test_mqtt_pubrec_packet_decode: Passed\n");
    }
    else
    {
        printf("test_mqtt_pubrec_packet_decode: Failed\n");
    }

    destroy_pubrec(mqtt_pkt_pubrec_decoded);
    printf("destroy_pubrec_decoded\n");
    return 0;

}

int test_mqtt_pubrel_packet_encode(uint8_t *encoded_buf, int* buf_len) {
    int packet_id = 3;
    // Create a test packet with specific values
    MQTT_PKT_PUBREL *mqtt_pkt_pubrel = mqtt_pkt_pubrel_create();
    mqtt_pkt_pubrel_init(mqtt_pkt_pubrel, packet_id);

    // Encode the packet
    uint8_t buf[MQTT_PKT_MAX_SIZE] = {0};
    int pubrel_len = mqtt_pkt_pubrel->encode(mqtt_pkt_pubrel, buf);

    // for (int i = 0; i < pubrel_len; i++)
    // {
    //     printf("buf[%d] = 0x%x ", i, buf[i]);
    // }
    // printf("\n");

    uint8_t expected_buf[1024] = {0};

    // Fixed header
    uint8_t *p = expected_buf;

    // Fixed header
    int len = 0;
    int expected_len = 0;

    p[0] = 0x62;
    p[1] = 0;

    expected_len += 2;
    p+=2;
    int rem_len = 0;

    int var_header_len = encode_int(p, packet_id);
    rem_len += var_header_len;

    int rem_len_len = encode_rem_len(rem_len, expected_buf+1);
    expected_len = 1 + rem_len_len + var_header_len;

    // for (int i = 0; i < expected_len; i++)
    // {
    //     printf("expected_buf[%d] = 0x%x ", i, expected_buf[i]);
    // }
    // printf("\n");
    // printf("pubrel_len = %d\n", pubrel_len);
    // printf("expected_len = %d\n", expected_len);

    // Compare the encoded packet with the expected packet
    if (pubrel_len == expected_len && memcmp(buf, expected_buf, pubrel_len) == 0) {
        printf("test_mqtt_pubrel_packet_encode: Passed\n");
        *buf_len = pubrel_len;
        memcpy(encoded_buf, buf, pubrel_len);
    } else {
        printf("test_mqtt_pubrel_packet_encode: Failed\n");
    }

    // Free the test packet
    destroy_pubrel(mqtt_pkt_pubrel);

    printf("destroy_pubrel_encoded\n");
    return 0;
}

int test_mqtt_pubrel_packet_decode(uint8_t * buf, int len)
{
    MQTT_PKT_PUBREL* mqtt_pkt_pubrel_decoded = mqtt_pkt_pubrel_decode(buf, len);
    if (mqtt_pkt_pubrel_decoded == NULL)
    {
        printf("test_mqtt_pubrel_packet_decode: Failed\n");
        return -1;
    }

    if (mqtt_pkt_pubrel_decoded->get_pkt_id(mqtt_pkt_pubrel_decoded) == 3)
    {
        printf("test_mqtt_pubrel_packet_decode: Passed\n");
    }
    else
    {
        printf("test_mqtt_pubrel_packet_decode: Failed\n");
    }

    destroy_pubrel(mqtt_pkt_pubrel_decoded);
    printf("destroy_pubrel_decoded\n");
    return 0;

}

int test_mqtt_pubcomp_packet_encode(uint8_t *encoded_buf, int* buf_len) {
    int packet_id = 3;
    // Create a test packet with specific values
    MQTT_PKT_PUBCOMP *mqtt_pkt_pubcomp = mqtt_pkt_pubcomp_create();
    mqtt_pkt_pubcomp_init(mqtt_pkt_pubcomp, packet_id);

    // Encode the packet
    uint8_t buf[MQTT_PKT_MAX_SIZE] = {0};
    int pubcomp_len = mqtt_pkt_pubcomp->encode(mqtt_pkt_pubcomp, buf);

    // for (int i = 0; i < pubcomp_len; i++)
    // {
    //     printf("buf[%d] = 0x%x ", i, buf[i]);
    // }
    // printf("\n");

    uint8_t expected_buf[1024] = {0};

    // Fixed header
    uint8_t *p = expected_buf;

    // Fixed header
    int len = 0;
    int expected_len = 0;

    p[0] = 0x70;
    p[1] = 0;

    expected_len += 2;
    p+=2;
    int rem_len = 0;

    int var_header_len = encode_int(p, packet_id);
    rem_len += var_header_len;

    int rem_len_len = encode_rem_len(rem_len, expected_buf+1);
    expected_len = 1 + rem_len_len + var_header_len;

    // for (int i = 0; i < expected_len; i++)
    // {
    //     printf("expected_buf[%d] = 0x%x ", i, expected_buf[i]);
    // }
    // printf("\n");
    // printf("pubcomp_len = %d\n", pubcomp_len);
    // printf("expected_len = %d\n", expected_len);

    // Compare the encoded packet with the expected packet
    if (pubcomp_len == expected_len && memcmp(buf, expected_buf, pubcomp_len) == 0) {
        printf("test_mqtt_pubcomp_packet_encode: Passed\n");
        *buf_len = pubcomp_len;
        memcpy(encoded_buf, buf, pubcomp_len);
    } else {
        printf("test_mqtt_pubcomp_packet_encode: Failed\n");
    }

    // Free the test packet
    destroy_pubcomp(mqtt_pkt_pubcomp);

    printf("destroy_pubcomp_encoded\n");
    return 0;
}

int test_mqtt_pubcomp_packet_decode(uint8_t * buf, int len)
{
    MQTT_PKT_PUBCOMP* mqtt_pkt_pubcomp_decoded = mqtt_pkt_pubcomp_decode(buf, len);
    if (mqtt_pkt_pubcomp_decoded == NULL)
    {
        printf("test_mqtt_pubcomp_packet_decode: Failed\n");
        return -1;
    }

    if (mqtt_pkt_pubcomp_decoded->get_pkt_id(mqtt_pkt_pubcomp_decoded) == 3)
    {
        printf("test_mqtt_pubcomp_packet_decode: Passed\n");
    }
    else
    {
        printf("test_mqtt_pubcomp_packet_decode: Failed\n");
    }

    destroy_pubcomp(mqtt_pkt_pubcomp_decoded);
    printf("destroy_pubcomp_decoded\n");
    return 0;

}


int test_mqtt_subscribe_packet_encode(uint8_t *encoded_buf, int* buf_len) {
    int packet_id = 8;
    // Create a test packet with specific values
    MQTT_PKT_SUBSCRIBE *mqtt_pkt_subscribe = mqtt_pkt_subscribe_create(packet_id);
    TOPIC_QOS init_topic_qos = {
        .topic = "test_topic",
        .qos = 1
    };

    mqtt_pkt_subscribe_init(mqtt_pkt_subscribe, &init_topic_qos);

    // Encode the packet
    uint8_t buf[MQTT_PKT_MAX_SIZE] = {0};
    int subscribe_len = mqtt_pkt_subscribe->encode(mqtt_pkt_subscribe, buf);

    // for (int i = 0; i < subscribe_len; i++)
    // {
    //     printf("buf[%d] = 0x%x ", i, buf[i]);
    // }
    // printf("\n");

    uint8_t expected_buf[1024] = {0};
    uint8_t *var_header = malloc(2);


    // Fixed header
    uint8_t *p = expected_buf;

    //var header
    int var_header_len = encode_int(p, packet_id);
    memcpy(var_header, p, var_header_len);
    p = expected_buf;

    //payload
    int topic_cnt = 1;
    int payload_len = 0;
    int topic_len = encode_string(p, init_topic_qos.topic);
    p+=topic_len;
    p[0] = init_topic_qos.qos;
    payload_len = topic_len + 1;
    p+=1;
    uint8_t *payload = malloc(payload_len);
    memcpy(payload, expected_buf, payload_len);
    memset(expected_buf, 0, sizeof(expected_buf));

    // Fixed header
    p = expected_buf;
    p[0] = 0x82;
    p += 1;
    int rem_len = var_header_len + payload_len;

    int rem_len_len = encode_rem_len(rem_len, p);
    p += rem_len_len;
    memcpy(p, var_header, var_header_len);
    p += var_header_len;
    memcpy(p, payload, payload_len);
    int expected_len = 1 + rem_len_len + var_header_len + payload_len;

    // for (int i = 0; i < expected_len; i++)
    // {
    //     printf("buf_[%d] = 0x%x ", i, expected_buf[i]);
    // }
    // printf("\n");

    free(var_header);
    free(payload);
    payload = NULL;
    var_header = NULL;

    // Compare the encoded packet with the expected packet
    if (subscribe_len == expected_len && memcmp(buf, expected_buf, subscribe_len) == 0) {
        printf("test_mqtt_subscribe_packet_encode: Passed\n");
        *buf_len = subscribe_len;
        // memcpy(encoded_buf, buf, subscribe_len);
    } else {
        printf("test_mqtt_subscribe_packet_encode: Failed\n");
    }

    printf("add begin\n");

    //add test
    TOPIC_QOS topic2 = {
        .topic = "test_topic2",
        .qos = 2
    };

    mqtt_pkt_subscribe->add_topic(mqtt_pkt_subscribe, topic2.topic, topic2.qos);

    // Encode the packet
    memset(buf, 0, MQTT_PKT_MAX_SIZE);
    subscribe_len = mqtt_pkt_subscribe->encode(mqtt_pkt_subscribe, buf);

    // for (int i = 0; i < subscribe_len; i++)
    // {
    //     printf("buf[%d] = 0x%x ", i, buf[i]);
    // }
    // printf("\n");

    memset(expected_buf, 0, sizeof(expected_buf));
    p = expected_buf;

    //var header
    var_header_len = encode_int(p, packet_id);
    uint8_t *var_header2 = malloc(2);
    memcpy(var_header2, p, var_header_len);
    p = expected_buf;

    
    //payload
    topic_cnt = 2;
    payload_len = 0;
    topic_len = encode_string(p, init_topic_qos.topic);
    p+=topic_len;
    p[0] = init_topic_qos.qos;
    payload_len += topic_len + 1;
    p+=1;
    topic_len = encode_string(p, topic2.topic);
    p+=topic_len;
    p[0] = topic2.qos;
    payload_len += topic_len + 1;
    p+=1;

    uint8_t* payload2 = malloc(payload_len);
    memcpy(payload2, expected_buf, payload_len);

    // Fixed header
    p = expected_buf;
    p[0] = 0x82;
    p += 1;
    rem_len = var_header_len + payload_len;

    rem_len_len = encode_rem_len(rem_len, p);
    p += rem_len_len;
    memcpy(p, var_header2, var_header_len);
    p += var_header_len;
    memcpy(p, payload2, payload_len);
    expected_len = 1 + rem_len_len + var_header_len + payload_len;

    free(var_header2);
    free(payload2);

    // for (int i = 0; i < expected_len; i++)
    // {
    //     printf("buf[%d] = 0x%x ", i, expected_buf[i]);
    // }
    // printf("\n");

    // Compare the encoded packet with the expected packet
    if (subscribe_len == expected_len && memcmp(buf, expected_buf, subscribe_len) == 0) {
        printf("test_mqtt_subscribe_packet_encode: Passed\n");
        *buf_len = subscribe_len;
        printf("topic1: %s %d\n", init_topic_qos.topic, init_topic_qos.qos);
        printf("topic2: %s %d\n", topic2.topic, topic2.qos);
        memcpy(encoded_buf, buf, subscribe_len);
    } else {
        printf("test_mqtt_subscribe_packet_encode: Failed\n");
    }

    // Free the test packet
    destroy_subscribe(mqtt_pkt_subscribe);

    printf("destroy_subscribe_encoded\n");
    return 0;
}

int test_mqtt_subscribe_packet_decode(uint8_t * buf, int len)
{
    MQTT_PKT_SUBSCRIBE* mqtt_pkt_subscribe_decoded = mqtt_pkt_subscribe_decode(buf, len);
    if (mqtt_pkt_subscribe_decoded == NULL)
    {
        printf("test_mqtt_subscribe_packet_decode: Failed\n");
        return -1;
    }

    TOPIC_QOS *topic = mqtt_pkt_subscribe_decoded->get_topic(mqtt_pkt_subscribe_decoded);
    while (topic != NULL)
    {
        printf("topic: %s %d\n", topic->topic, topic->qos);
        topic = topic->next;
    }

    destroy_subscribe(mqtt_pkt_subscribe_decoded);
    printf("destroy_subscribe_decoded\n");
    return 0;

}

int main() {
    uint8_t encoded_buf[1024] = {0};
    int buf_len = 0;
    test_mqtt_connect_packet_encode(encoded_buf, &buf_len);
    test_mqtt_connect_packet_decode(encoded_buf, buf_len);
    memset(encoded_buf, 0, 1024);
    test_mqtt_connact_packet_encode(encoded_buf, &buf_len);
    test_mqtt_connack_packet_decode(encoded_buf, buf_len);
    memset(encoded_buf, 0, 1024);
    test_mqtt_publish_packet_encode(encoded_buf, &buf_len);
    test_mqtt_publish_packet_decode(encoded_buf, buf_len);
    memset(encoded_buf, 0, 1024);
    test_mqtt_puback_packet_encode(encoded_buf, &buf_len);
    test_mqtt_puback_packet_decode(encoded_buf, buf_len);
    memset(encoded_buf, 0, 1024);
    test_mqtt_pubrec_packet_encode(encoded_buf, &buf_len);
    test_mqtt_pubrec_packet_decode(encoded_buf, buf_len);
    memset(encoded_buf, 0, 1024);
    test_mqtt_pubrel_packet_encode(encoded_buf, &buf_len);
    test_mqtt_pubrel_packet_decode(encoded_buf, buf_len);
    memset(encoded_buf, 0, 1024);
    test_mqtt_pubcomp_packet_encode(encoded_buf, &buf_len);
    test_mqtt_pubcomp_packet_decode(encoded_buf, buf_len);
    memset(encoded_buf, 0, 1024);
    test_mqtt_subscribe_packet_encode(encoded_buf, &buf_len);
    test_mqtt_subscribe_packet_decode(encoded_buf, buf_len);

    return 0;
}