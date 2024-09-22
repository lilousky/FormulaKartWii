#include "wiilink.h"
#include "common.h"
#include "ipc.h"
#include "nhttp.h"
#include "stdlib.h"
#include <vendor/sha256.h>
#include <vendor/rsa.h>

static u8 s_payloadBlock[PAYLOAD_BLOCK_SIZE + 0x20];
static void* s_payload = NULL;
static bool s_payloadReady = false;
static u8 s_saltHash[SHA256_DIGEST_SIZE];
// 
extern u32 DWCi_Auth_SendRequest;
void DWCi_Auth_SendRequest_Replaced(int param_1, int param_2, int param_3, int param_4, int param_5, int param_6);

bool GenerateRandomSalt(u8 *out) {
    OSReport("GenerateRandomSalt\n");
    // Generate cryptographic random with ES_Sign
    s32 fd = IOS_Open("/dev/es", IPC_OPEN_NONE);
    if (fd < 0) {
        return false;
    }
    u8 dummy = 0x7a;
    u8 eccCert[0x180];
    u8 eccSignature[0x3C];

    IOVector vec[3];
    vec[0].data = &dummy;
    vec[0].size = 1;
    vec[1].data = eccSignature;
    vec[1].size = 0x3C;
    vec[2].data = eccCert;
    vec[2].size = 0x180;

    // ES_Sign
    s32 ret = IOS_Ioctlv(fd, 0x30, 1, 2, vec);
    IOS_Close(fd);

    if (ret < 0) {
        return false;
    }

    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, eccSignature, 0x3C);
    sha256_update(&ctx, eccCert, 0x180);
    memcpy(out, sha256_final(&ctx), SHA256_DIGEST_SIZE);
    return true;
}

s32 HandleResponse(u8* block){
    OSReport("HandleResponse\n");
    register wwfc_payload* __restrict payload = (wwfc_payload*)block;

    if (*(u32*)payload != 0x57574643 /* WWFC */) {
        return WL_ERROR_PAYLOAD_STAGE1_HEADER_CHECK;
    }

    if (payload->header.total_size < sizeof(wwfc_payload) ||
        payload->header.total_size > PAYLOAD_BLOCK_SIZE) {
        return WL_ERROR_PAYLOAD_STAGE1_LENGTH_ERROR;
    }

    if (memcmp(payload->salt, s_saltHash, SHA256_DIGEST_SIZE) != 0) {
        return WL_ERROR_PAYLOAD_STAGE1_SALT_MISMATCH;
    }
    OSReport("Payload salt verified\n");
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (u8*)(payload) + sizeof(wwfc_payload_header), payload->header.total_size - sizeof(wwfc_payload_header));
    u8* hash = sha256_final(&ctx);
    OSReport("Payload hash calculated\n");

    if (!rsa_verify((const struct rsa_public_key*)PayloadPublicKey, payload->header.signature, hash)) {
        OSReport("Payload signature invalid\n");
        return WL_ERROR_PAYLOAD_STAGE1_SIGNATURE_INVALID;
    }
    OSReport("Payload signature verified\n");

    // Flush data cache and invalidate instruction cache
        for (u32 i = 0; i < 0x20000; i += 0x20) {
            asm volatile("dcbf %0, %1\n"
                         "sync\n"
                         "icbi %0, %1\n"
                         "isync\n"
                         :
                         : "r"(i), "r"(payload));
        }
    OSReport("Cache flushed\n");
    // Todo - maybe implement disabling some of the patches
    s32 (*entryFunction)(wwfc_payload*) = (s32 (*)(wwfc_payload*))( (u8*)(payload) + payload->info.entry_point );
    OSReport("Calling entry function\n");
    return entryFunction(payload);
}

void OnPayloadReceived(s32 result, void* response, void* userdata) {
    OSReport("OnPayloadReceived\n");
    if (response == NULL) {
    return;
    }
    NHTTPDestroyResponse(response);

    if (result != 0) {
        return;
    }

    s32 error = HandleResponse((u8*)s_payload);
    if (error != 0) {
        s_auth_error = error;
        return;
    }
    s_payloadReady = true;
    s_auth_error = -1; // This error code will retry auth
}



// Hooks DWCi_Auth_SendRequest
void wwfcStage1(int param_1, int param_2, int param_3, int param_4, int param_5, int param_6){
    OSReport("wwfcStage1\n");
    if (s_payloadReady) {
        // If the payload is already ready, call the original function
        OSReport("Calling original function\n");
        DWCi_Auth_SendRequest_Replaced(param_1, param_2, param_3, param_4, param_5, param_6);
        return;
    }
    s_payload = (void*) (((u32)s_payloadBlock + 31) & ~31);
    memset(s_payload, 0, PAYLOAD_BLOCK_SIZE);
    u8 salt[SHA256_DIGEST_SIZE];
    if (!GenerateRandomSalt(salt)) {
        s_auth_error = WL_ERROR_PAYLOAD_STAGE1_MAKE_REQUEST;
    }
    static const char* hexConv = "0123456789abcdef";
    char saltHex[SHA256_DIGEST_SIZE * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        saltHex[i * 2] = hexConv[salt[i] >> 4];
         saltHex[i * 2 + 1] = hexConv[salt[i] & 0xf];
    }
    saltHex[SHA256_DIGEST_SIZE * 2] = 0;
    char uri[0x100];
    sprintf(uri, "payload?g=RMC%cD00&s=%s", *(char*) 0x80000003, saltHex);

    // Generate salt hash
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, uri, strlen(uri));
    memcpy(s_saltHash, sha256_final(&ctx), SHA256_DIGEST_SIZE);
    char url[0x100];
    sprintf(url, "http://nas.%s/%s&h=%02x%02x%02x%02x", WIILINK_DOMAIN, uri, s_saltHash[0], s_saltHash[1], s_saltHash[2], s_saltHash[3]);
    void* request = NHTTPCreateRequest(url, 0, s_payload, PAYLOAD_BLOCK_SIZE, OnPayloadReceived, 0);
    if (request == NULL) {
        s_auth_error = WL_ERROR_PAYLOAD_STAGE1_MAKE_REQUEST;
        return;
    }
    s_auth_work[0x59E0 / 4] = NHTTPSendRequestAsync(request);
    OSReport("End of stage1\n");
    asm volatile("blr");
}
