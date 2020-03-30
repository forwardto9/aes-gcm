#pragma once
#include <stddef.h>

int memcmp(const void* s1, const void* s2, size_t n);
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
int strcmp(const char* s1, const char* s2);

/// 十六进制字符串转换为字符数组
/// @param input 16进制字符串，例如：“a0b199ff”
/// @param output 字符数组
/// @return 0 成功，其他失败
int hexstringtobyte(char *input, unsigned char *output);

/// 字符数组转换为16进制字符串
/// @param input 字符数组
/// @param len 字符数组长度
/// @param output 16进制结果
/// @return 0 成功，其他失败
int bytetohexstring(unsigned char *input, int len, char *output);
