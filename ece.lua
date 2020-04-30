local ffi = require 'ffi'
local ece = ffi.load("/usr/lib/libece.so")

C = ffi.C

local ECE_SALT_LENGTH = 16
local ECE_TAG_LENGTH = 16
local ECE_WEBPUSH_PRIVATE_KEY_LENGTH = 32
local ECE_WEBPUSH_PUBLIC_KEY_LENGTH = 65
local ECE_WEBPUSH_AUTH_SECRET_LENGTH = 16
local ECE_WEBPUSH_DEFAULT_RS = 4096

local ECE_AES128GCM_MIN_RS = 18
local ECE_AES128GCM_HEADER_LENGTH = 21
local ECE_AES128GCM_MAX_KEY_ID_LENGTH = 255
local ECE_AES128GCM_PAD_SIZE = 1

local ECE_AESGCM_MIN_RS = 3
local ECE_AESGCM_PAD_SIZE = 2

local ECE_OK = 0
local ECE_ERROR_OUT_OF_MEMORY = -1
local ECE_ERROR_INVALID_PRIVATE_KEY = -2
local ECE_ERROR_INVALID_PUBLIC_KEY = -3
local ECE_ERROR_COMPUTE_SECRET = -4
local ECE_ERROR_ENCODE_PUBLIC_KEY = -5
local ECE_ERROR_DECRYPT = -6
local ECE_ERROR_DECRYPT_PADDING = -7
local ECE_ERROR_ZERO_PLAINTEXT = -8
local ECE_ERROR_SHORT_BLOCK = -9
local ECE_ERROR_SHORT_HEADER = -10
local ECE_ERROR_ZERO_CIPHERTEXT = -11
local ECE_ERROR_HKDF = -12
local ECE_ERROR_INVALID_ENCRYPTION_HEADER = -13
local ECE_ERROR_INVALID_CRYPTO_KEY_HEADER = -14
local ECE_ERROR_INVALID_RS = -15
local ECE_ERROR_INVALID_SALT = -16
local ECE_ERROR_INVALID_DH = -17
local ECE_ERROR_ENCRYPT = -18
local ECE_ERROR_ENCRYPT_PADDING = -19
local ECE_ERROR_INVALID_AUTH_SECRET = -20
local ECE_ERROR_GENERATE_KEYS = -21
local ECE_ERROR_DECRYPT_TRUNCATED = -22

local ECE_BASE64URL_OMIT_PADDING = 0
local ECE_BASE64URL_INCLUDE_PADDING = 1

local ECE_BASE64URL_REQUIRE_PADDING = 0 
local ECE_BASE64URL_IGNORE_PADDING = 1
local ECE_BASE64URL_REJECT_PADDING = 2 

ffi.cdef[[
    typedef enum ece_base64url_encode_policy_e {
        ECE_BASE64URL_OMIT_PADDING,
        ECE_BASE64URL_INCLUDE_PADDING,
    } ece_base64url_encode_policy_t;

    typedef enum ece_base64url_decode_policy_e {
        ECE_BASE64URL_REQUIRE_PADDING,
        ECE_BASE64URL_IGNORE_PADDING,
        ECE_BASE64URL_REJECT_PADDING,
    } ece_base64url_decode_policy_t;

    int ece_webpush_generate_keys(uint8_t* rawRecvPrivKey, size_t rawRecvPrivKeyLen,
                          uint8_t* rawRecvPubKey, size_t rawRecvPubKeyLen,
                          uint8_t* authSecret, size_t authSecretLen);
                          
    size_t ece_base64url_encode(const void* binary, size_t binaryLen,
                        ece_base64url_encode_policy_t paddingPolicy, char* base64,
                        size_t base64Len);
    size_t ece_base64url_decode(const char* base64, size_t base64Len,
                        ece_base64url_decode_policy_t paddingPolicy,
                        uint8_t* binary, size_t binaryLen);

    size_t ece_aes128gcm_payload_max_length(uint32_t rs, size_t padLen,
                                        size_t plaintextLen);
    int ece_webpush_aes128gcm_encrypt(const uint8_t* rawRecvPubKey,
                                    size_t rawRecvPubKeyLen,
                                    const uint8_t* authSecret, size_t authSecretLen,
                                    uint32_t rs, size_t padLen,
                                    const uint8_t* plaintext, size_t plaintextLen,
                                    uint8_t* payload, size_t* payloadLen);
    size_t ece_aes128gcm_plaintext_max_length(const uint8_t* payload, size_t payloadLen);
    int ece_webpush_aes128gcm_decrypt(const uint8_t* rawRecvPrivKey,
                              size_t rawRecvPrivKeyLen,
                              const uint8_t* authSecret, size_t authSecretLen,
                              const uint8_t* payload, size_t payloadLen,
                              uint8_t* plaintext, size_t* plaintextLen);
]]

local function base64url_encode(binary, binaryLen, paddingPolicy)
    local rlen = ece.ece_base64url_encode(binary, binaryLen, paddingPolicy, nil, 0)
    local base64 = ffi.new("uint8_t[?]", rlen + 1)
    assert(base64)
    local actualBase64Len = ece.ece_base64url_encode(binary, binaryLen, paddingPolicy, base64, rlen)
    assert(actualBase64Len ~= 0)
    return ffi.string(base64),actualBase64Len
end

local function generate_keys()
    local rawRecvPrivKey = ffi.new("uint8_t[?]", ECE_WEBPUSH_PRIVATE_KEY_LENGTH)
    local rawRecvPubKey = ffi.new("uint8_t[?]", ECE_WEBPUSH_PUBLIC_KEY_LENGTH)
    local authSecret = ffi.new("uint8_t[?]", ECE_WEBPUSH_AUTH_SECRET_LENGTH)

    local err = ece.ece_webpush_generate_keys(rawRecvPrivKey,ECE_WEBPUSH_PRIVATE_KEY_LENGTH,
                                        rawRecvPubKey,ECE_WEBPUSH_PUBLIC_KEY_LENGTH,
                                        authSecret,ECE_WEBPUSH_AUTH_SECRET_LENGTH)

    local RecvPrivKey = base64url_encode(rawRecvPrivKey,ECE_WEBPUSH_PRIVATE_KEY_LENGTH,ECE_BASE64URL_OMIT_PADDING)
    local RecvPubKey = base64url_encode(rawRecvPubKey,ECE_WEBPUSH_PUBLIC_KEY_LENGTH,ECE_BASE64URL_OMIT_PADDING)
    local Secret = base64url_encode(authSecret,ECE_WEBPUSH_AUTH_SECRET_LENGTH,ECE_BASE64URL_OMIT_PADDING)
    assert(err == ECE_OK,"ece_webpush_generate_keys error" .. err)
    -- = ffi.new("uint8_t[?]",ECE_WEBPUSH_PUBLIC_KEY_LENGTH)

    return RecvPrivKey,RecvPubKey,Secret
end

local function base64url_decode(base64, base64Len, paddingPolicy, binary, binaryLen)
    local size = ece.ece_base64url_decode(base64, base64Len, paddingPolicy, binary, binaryLen)
    return size
end

local function aes128gcm_payload_max_length(rs, padLen, plaintextLen)
    return ece.ece_aes128gcm_payload_max_length(rs, padLen, plaintextLen)
end

local function aes128gcm_encrypt(rawRecvPubKey, rawRecvPubKeyLen,
                                    authSecret, authSecretLen,
                                    rs,  padLen,
                                    plaintext,  plaintextLen,
                                    payload,  payloadLen)
    local plen = ffi.new("size_t[1]", payloadLen)
    local ret =  ece.ece_webpush_aes128gcm_encrypt(rawRecvPubKey, rawRecvPubKeyLen,
                authSecret, authSecretLen,
                rs,  padLen,
                plaintext,  plaintextLen,
                payload,  plen)
    return ret,tonumber(plen[0])
end

local function aes128gcm_plaintext_max_length(payload, payloadLen)
    return ece.ece_aes128gcm_plaintext_max_length(payload, payloadLen)
end

local function aes128gcm_decrypt(rawRecvPrivKey,
                                    rawRecvPrivKeyLen,
                                    authSecret, authSecretLen,
                                    payload,  payloadLen,
                                    plaintext,  plaintextLen)
    local plen = ffi.new("size_t[1]", plaintextLen)
    local ret = ece.ece_webpush_aes128gcm_decrypt(rawRecvPrivKey,
                            rawRecvPrivKeyLen,
                            authSecret, authSecretLen,
                            payload,  payloadLen,
                            plaintext,  plen)
    
    return ret,tonumber(plen[0])
end

return {
    generate_keys                           = generate_keys,
    base64url_encode                        = base64url_encode,
    base64url_decode                        = base64url_decode,
    aes128gcm_payload_max_length            = aes128gcm_payload_max_length,
    aes128gcm_encrypt                       = aes128gcm_encrypt,
    aes128gcm_plaintext_max_length          = aes128gcm_plaintext_max_length,
    aes128gcm_decrypt                       = aes128gcm_decrypt,
}