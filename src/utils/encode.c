#include "encode.h"

#include <string.h>

int encode_string(unsigned char * buffer, const char * string)
{
    if (buffer == NULL || string == NULL)
    {
        return -1;
    }
    
    int len = strlen(string);
    buffer[0] = (len >> 8) & 0xFF;
    buffer[1] = len & 0xFF;
    memcpy(buffer + 2, string, len);
    return len + 2;
}

int encode_int(unsigned char * buffer, int value)
{
    if (buffer == NULL)
    {
        return -1;
    }
    
    buffer[0] = (value >> 8);
    buffer[1] = value & 0xFF;

    return 2;
}

int decode_len(unsigned char * buffer, int * value)
{
    if (buffer == NULL || value == NULL)
    {
        return -1;
    }
    
    *value = (buffer[0] << 8) + buffer[1];
    return 2;
}

int decode_string(unsigned char * buffer, char * string)
{
    if (buffer == NULL || string == NULL)
    {
        return -1;
    }
    
    int len = (buffer[0] << 8) + buffer[1];
    memcpy(string, buffer + 2, len);
    string[len] = '\0';
    return len + 2;
}


int encode_rem_len(int rem_len, unsigned char *buf)
{
    int i = 0;
    do
    {
        buf[i] = rem_len % 128;
        rem_len = rem_len / 128;
        if (rem_len > 0)
        {
            buf[i] = buf[i] | 0x80;
        }
        i++;
    }while(rem_len > 0);
    return i;
}

int decode_rem_len(unsigned char *buf, int *rem_len)
{
    int multiplier = 1;
    *rem_len = 0;
    int i = 0;
    do
    {
        *rem_len += (buf[i] & 0x7F) * multiplier;
        multiplier *= 128;
        i++;
    }while((buf[i] & 0x80) != 0);
    return i;
}
