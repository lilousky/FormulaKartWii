#pragma once
#include "common.h"

int sprintf(char *, const char *, ...);
int snprintf(char* buffer, int length, char* format, ...);
size_t strlen(const char *);
void* new(u32 size, u32 align);
void delete(void* buffer);
void* memcpy(void* dest, const void* src, size_t);
int memcmp(const void*, const void*, size_t);
void* memset(void*, int, size_t);
