// Documentation by Melg
#pragma once
#include "common.h"
s32 NHTTPStartup(void* alloc, void* free, u32 param_3);

void* NHTTPCreateRequest(const char* url, int param_2, void* buffer, u32 length, void* callback, void* userdata);

s32 NHTTPSendRequestAsync(void* request);

s32 NHTTPDestroyResponse(void* response);