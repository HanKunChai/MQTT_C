/*********************
 * @file:    mqtt_pkt.h
 * @brief:   MQTT packet functions and structures
 * @date:    July 2024
 * @version: 1.0
 * *********************/


/*pkt marcos*/
#define MQTT_PKT_MAX_SIZE 1024


/*MQTT packet types*/
enum mqtt_pkt_type {
    MQTT_PKT_TYPE_CONNECT = 1,
    MQTT_PKT_TYPE_CONNACK = 2,
    MQTT_PKT_TYPE_PUBLISH = 3,
    MQTT_PKT_TYPE_PUBACK = 4,
    MQTT_PKT_TYPE_PUBREC = 5,
    MQTT_PKT_TYPE_PUBREL = 6,
    MQTT_PKT_TYPE_PUBCOMP = 7,
    MQTT_PKT_TYPE_SUBSCRIBE = 8,
    MQTT_PKT_TYPE_SUBACK = 9,
    MQTT_PKT_TYPE_UNSUBSCRIBE = 10,
    MQTT_PKT_TYPE_UNSUBACK = 11,
    MQTT_PKT_TYPE_PINGREQ = 12,
    MQTT_PKT_TYPE_PINGRESP = 13,
    MQTT_PKT_TYPE_DISCONNECT = 14
};

/*MQTT packet structure*/





