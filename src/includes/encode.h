


int encode_int(unsigned char * buffer, int value);
int decode_len(unsigned char *buffer, int *value);
int decode_string(unsigned char *buffer, char *string);
int encode_rem_len(int rem_len, unsigned char *buf);
int decode_rem_len(unsigned char *buf, int *rem_len);
int encode_string(unsigned char *buffer, const char *string);

