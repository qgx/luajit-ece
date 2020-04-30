local ffi = require 'ffi'

C = ffi.C

local ece = require 'ece'

local generate_keys                           = ece.generate_keys
local base64url_encode                        = ece.base64url_encode
local base64url_decode                        = ece.base64url_decode
local aes128gcm_payload_max_length            = ece.aes128gcm_payload_max_length
local aes128gcm_encrypt                       = ece.aes128gcm_encrypt
local aes128gcm_plaintext_max_length          = ece.aes128gcm_plaintext_max_length
local aes128gcm_decrypt                       = ece.aes128gcm_decrypt

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

local function test_generate_keys()
    local ok,rawRecvPrivKey,rawRecvPubKey,authSecret = pcall(generate_keys)
    assert(ok,"generate_keys error,"..tostring(rawRecvPrivKey))
    print("generate_keys success. ".. string.len(ffi.string(rawRecvPrivKey)) .. " " .. string.len(ffi.string(rawRecvPubKey)) .. " " .. string.len(ffi.string(authSecret)))
    print("rawRecvPrivKey " .. ffi.string(rawRecvPrivKey))
    print("rawRecvPubKey " .. tostring(rawRecvPubKey))
    print("authSecret " .. tostring(authSecret))
    return rawRecvPrivKey,rawRecvPubKey,authSecret
end

local function test_base64url_decode()
    local p256dh = "BDwwYm4O5dZG9SO6Vaz168iDLGWMmitkj5LFvunvMfgmI2fZdAEaiHTDfKR0fvr0D3V56cSGSeUwP0xNdrXho5k"
    local rawRecvPubKey = ffi.new("uint8_t[?]",ECE_WEBPUSH_PUBLIC_KEY_LENGTH)
    local size = base64url_decode(p256dh,string.len(p256dh),ECE_BASE64URL_REJECT_PADDING,rawRecvPubKey,ECE_WEBPUSH_PUBLIC_KEY_LENGTH)
    assert(size ~= 0,"base64url_decode error")
    print("test_base64url_decode sucess " .. tonumber(size) )
end

local function test_aes128gcm_Encryption(PubKey,auth)
    local endpoint = "https://updates.push.services.mozilla.com/...";
    local p256dh = PubKey

    local plaintext = "I'm just like my country, I'm young, scrappy, and hungry, and I'm not throwing away my shot.";
    local plaintextLen = string.len(plaintext)

    local padLen = 0

    local rawRecvPubKey = ffi.new("uint8_t[?]",ECE_WEBPUSH_PUBLIC_KEY_LENGTH)
    local rawRecvPubKeyLen = base64url_decode(p256dh, string.len(p256dh), ECE_BASE64URL_REJECT_PADDING,
                            rawRecvPubKey, ECE_WEBPUSH_PUBLIC_KEY_LENGTH)
    assert(rawRecvPubKeyLen > 0)
    local authSecret = ffi.new("uint8_t[?]",ECE_WEBPUSH_AUTH_SECRET_LENGTH)
    local authSecretLen = base64url_decode(auth, string.len(auth), ECE_BASE64URL_REJECT_PADDING,
                            authSecret, ECE_WEBPUSH_AUTH_SECRET_LENGTH)
    assert(authSecretLen > 0)

    local payloadLen = aes128gcm_payload_max_length(ECE_WEBPUSH_DEFAULT_RS,
                                                        padLen, plaintextLen)
    assert(payloadLen > 0);
    local payload = ffi.new("uint8_t[?]",payloadLen)
    assert(payload)

    local err,plen = aes128gcm_encrypt(
        rawRecvPubKey, rawRecvPubKeyLen, authSecret, authSecretLen,
        ECE_WEBPUSH_DEFAULT_RS, padLen, plaintext, plaintextLen, payload,
        payloadLen)
    assert(err == ECE_OK)
    print("aes128gcm_encrypt sucess," .. plen)
    print(string.format(
        "curl -v -X POST -H \"Content-Encoding: aes128gcm\" --data-binary @%s %s\n",
        "filename", endpoint))
    return payload,plen
end

local function test_aes128gcm_Decryption(payload,payloadLen,SubPrivKey,Secret)
    local plaintextLen = aes128gcm_plaintext_max_length(payload,payloadLen)
    assert(plaintextLen > 0)
    local plaintext = ffi.new("uint8_t[?]",plaintextLen + 1)
    assert(plaintext);

    local rawSubPrivKey = ffi.new("uint8_t[?]",ECE_WEBPUSH_PRIVATE_KEY_LENGTH)
    local rawSubPrivKeyLen = base64url_decode(SubPrivKey, string.len(SubPrivKey), ECE_BASE64URL_REJECT_PADDING,
                                rawSubPrivKey, ECE_WEBPUSH_PRIVATE_KEY_LENGTH)
    assert(rawSubPrivKeyLen > 0)
    local rawSecret = ffi.new("uint8_t[?]",ECE_WEBPUSH_AUTH_SECRET_LENGTH)
    local rawSecretLen = base64url_decode(Secret, string.len(Secret), ECE_BASE64URL_REJECT_PADDING,
                                rawSecret, ECE_WEBPUSH_AUTH_SECRET_LENGTH)
    assert(rawSecretLen > 0)

    local err,plen = aes128gcm_decrypt(rawSubPrivKey, ECE_WEBPUSH_PRIVATE_KEY_LENGTH,
                                rawSecret, ECE_WEBPUSH_AUTH_SECRET_LENGTH,
                                payload, payloadLen, plaintext, plaintextLen)

    assert(err == ECE_OK)
    print("aes128gcm_Decryption sucess," .. plen)
    print(ffi.string(plaintext))
end

local function test()
    local rawRecvPrivKey,rawRecvPubKey,authSecret = test_generate_keys()
    test_base64url_decode()
    local payload,payloadLen = test_aes128gcm_Encryption(rawRecvPubKey,authSecret)
    test_aes128gcm_Decryption(payload,payloadLen,rawRecvPrivKey,authSecret)
end

test()