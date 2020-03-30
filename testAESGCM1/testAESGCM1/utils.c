#include "utils.h"
#include <stdlib.h>
void *memset(void *s, int c, size_t n)
{
    unsigned char* p=s;
    while(n--)
        *p++ = (unsigned char)c;
    return s;
}

void *memcpy(void *dest, const void *src, size_t n)
{
    char *dp = dest;
    const char *sp = src;
    while (n--)
        *dp++ = *sp++;
    return dest;
}

int memcmp(const void* s1, const void* s2,size_t n)
{
    const unsigned char *p1 = s1, *p2 = s2;
    while(n--)
        if( *p1 != *p2 )
            return *p1 - *p2;
        else
            (void)(p1++),p2++;
    return 0;
}

int strcmp(const char* s1, const char* s2)
{
    while(*s1 && (*s1==*s2))
        (void)(s1++),s2++;
    return *(const unsigned char*)s1-*(const unsigned char*)s2;
}

int hexstringtobyte(char *input, unsigned char *output) {
    int len = (int)strlen(input);
    char *str = (char *)malloc(len);
    memset(str, 0, len);
    memcpy(str, input, len);
    for (int i = 0; i < len; i+=2) {
        //小写转大写
        if(str[i] >= 'a' && str[i] <= 'f') str[i] = str[i] & ~0x20;
        if(str[i+1] >= 'a' && str[i] <= 'f') str[i+1] = str[i+1] & ~0x20;
        //处理第前4位
        if(str[i] >= 'A' && str[i] <= 'F')
            output[i/2] = (str[i]-'A'+10)<<4;
        else
            output[i/2] = (str[i] & ~0x30)<<4;
        //处理后4位, 并组合起来
        if(str[i+1] >= 'A' && str[i+1] <= 'F')
            output[i/2] |= (str[i+1]-'A'+10);
        else
            output[i/2] |= (str[i+1] & ~0x30);
    }
    free(str);
    return 0;
}

int bytetohexstring(unsigned char *input, int len, char *output) {
    for (int i = 0; i < len; i++) {
        if ((input[i] >> 4) >= 10 && (input[i] >> 4) <= 15)
            output[2*i] = (input[i] >> 4) + 'A' - 10;
        else
            output[2*i] = (input[i] >> 4) | 0x30;
        
        if ((input[i] & 0x0f) >= 10 && (input[i] & 0x0f) <= 15)
            output[2*i+1] = (input[i] & 0x0f) + 'A' - 10;
        else
            output[2*i+1] = (input[i] & 0x0f) | 0x30;
    }
    return 0;
}
