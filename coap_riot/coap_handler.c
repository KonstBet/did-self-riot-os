/*
 * Copyright (C) 2016 Kaspar Schleiser <kaspar@schleiser.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "fmt.h"
#include "net/nanocoap.h"
#include "hashes/sha256.h"
#include "kernel_defines.h"

#include "edsign.h"
#include "ed25519.h"
#include "random.h"
#include "base64.h"

/* digital signature key pair */ /* Generated using ed25519-genkeypair */
static char* secret_key_base64;
static uint8_t secret_key_hex[100] = { 0 };
// static uint8_t secret_key[EDSIGN_SECRET_KEY_SIZE] = { 0 };
static char* public_key_base64;
static uint8_t public_key_hex[100] = { 0 };
// static uint8_t public_key[EDSIGN_PUBLIC_KEY_SIZE] = { 0 };

/* hardcoded digital signature key pair */
static uint8_t secret_key_hex_hardcoded[100] = "8bb4014d8b0a63af72d88482c1276ccd032e26fc05806886a9f1a727210f4fc3";
//static uint8_t secret_key_hex_hardcoded[EDSIGN_SECRET_KEY_SIZE] = { 0 };

static uint8_t public_key_hex_hardcoded[100] = "d04e907192471c603e148d73d6a3897976dc260106aa120837ebcf815f0445c2";
//static uint8_t public_key_hex_hardcoded[EDSIGN_PUBLIC_KEY_SIZE] = { 0 };

/* internal value that can be read/written via CoAP */
static uint8_t internal_value = 0;

static const uint8_t block2_intro[] = "This is RIOT (Version: ";
static const uint8_t block2_board[] = " running on a ";
static const uint8_t block2_mcu[] = " board with a ";

static ssize_t _echo_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;
    char uri[CONFIG_NANOCOAP_URI_MAX];

    if (coap_get_uri_path(pkt, (uint8_t *)uri) <= 0) {
        return coap_reply_simple(pkt, COAP_CODE_INTERNAL_SERVER_ERROR, buf,
                                 len, COAP_FORMAT_TEXT, NULL, 0);
    }
    char *sub_uri = uri + strlen("/echo/");
    size_t sub_uri_len = strlen(sub_uri);
    return coap_reply_simple(pkt, COAP_CODE_CONTENT, buf, len, COAP_FORMAT_TEXT,
                             (uint8_t *)sub_uri, sub_uri_len);
}

static ssize_t _riot_board_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len,
            COAP_FORMAT_TEXT, (uint8_t*)RIOT_BOARD, strlen(RIOT_BOARD));
}

static ssize_t _riot_block2_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;
    coap_block_slicer_t slicer;
    coap_block2_init(pkt, &slicer);
    uint8_t *payload = buf + coap_get_total_hdr_len(pkt);

    uint8_t *bufpos = payload;

    bufpos += coap_put_option_ct(bufpos, 0, COAP_FORMAT_TEXT);
    bufpos += coap_opt_put_block2(bufpos, COAP_OPT_CONTENT_FORMAT, &slicer, 1);
    *bufpos++ = 0xff;

    /* Add actual content */
    bufpos += coap_blockwise_put_bytes(&slicer, bufpos, block2_intro, sizeof(block2_intro)-1);
    bufpos += coap_blockwise_put_bytes(&slicer, bufpos, (uint8_t*)RIOT_VERSION, strlen(RIOT_VERSION));
    bufpos += coap_blockwise_put_char(&slicer, bufpos, ')');
    bufpos += coap_blockwise_put_bytes(&slicer, bufpos, block2_board, sizeof(block2_board)-1);
    bufpos += coap_blockwise_put_bytes(&slicer, bufpos, (uint8_t*)RIOT_BOARD, strlen(RIOT_BOARD));
    bufpos += coap_blockwise_put_bytes(&slicer, bufpos, block2_mcu, sizeof(block2_mcu)-1);
    bufpos += coap_blockwise_put_bytes(&slicer, bufpos, (uint8_t*)RIOT_MCU, strlen(RIOT_MCU));
    /* To demonstrate individual chars */
    bufpos += coap_blockwise_put_char(&slicer, bufpos, ' ');
    bufpos += coap_blockwise_put_char(&slicer, bufpos, 'M');
    bufpos += coap_blockwise_put_char(&slicer, bufpos, 'C');
    bufpos += coap_blockwise_put_char(&slicer, bufpos, 'U');
    bufpos += coap_blockwise_put_char(&slicer, bufpos, '.');

    unsigned payload_len = bufpos - payload;
    return coap_block2_build_reply(pkt, COAP_CODE_205,
                                   buf, len, payload_len, &slicer);
}

static ssize_t _riot_value_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void) context;

    ssize_t p = 0;
    char rsp[16];
    unsigned code = COAP_CODE_EMPTY;

    /* read coap method type in packet */
    unsigned method_flag = coap_method2flag(coap_get_code_detail(pkt));

    switch(method_flag) {
    case COAP_GET:
        /* write the response buffer with the internal value */
        p += fmt_u32_dec(rsp, internal_value);
        code = COAP_CODE_205;
        break;
    case COAP_PUT:
    case COAP_POST:
        if (pkt->payload_len < 16) {
            /* convert the payload to an integer and update the internal value */
            char payload[16] = { 0 };
            memcpy(payload, (char*)pkt->payload, pkt->payload_len);
            internal_value = strtol(payload, NULL, 10);
            code = COAP_CODE_CHANGED;
        }
        else {
            code = COAP_CODE_REQUEST_ENTITY_TOO_LARGE;
        }
    }

    return coap_reply_simple(pkt, code, buf, len,
            COAP_FORMAT_TEXT, (uint8_t*)rsp, p);
}

ssize_t _sha256_handler(coap_pkt_t* pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;

    /* using a shared sha256 context *will* break if two requests are handled
     * at the same time.  doing it anyways, as this is meant to showcase block1
     * support, not proper synchronisation. */
    static sha256_context_t sha256;

    uint8_t digest[SHA256_DIGEST_LENGTH];

    uint32_t result = COAP_CODE_204;

    coap_block1_t block1;
    int blockwise = coap_get_block1(pkt, &block1);

    printf("_sha256_handler(): received data: offset=%u len=%u blockwise=%i more=%i\n", \
            (unsigned)block1.offset, pkt->payload_len, blockwise, block1.more);

    if (block1.offset == 0) {
        puts("_sha256_handler(): init");
        sha256_init(&sha256);
    }

    sha256_update(&sha256, pkt->payload, pkt->payload_len);

    if (block1.more == 1) {
        result = COAP_CODE_CONTINUE;
    }

    size_t result_len = 0;
    if (!blockwise || !block1.more) {
        puts("_sha256_handler(): finish");
        sha256_final(&sha256, digest);
        result_len = SHA256_DIGEST_LENGTH * 2;
    }

    ssize_t reply_len = coap_build_reply(pkt, result, buf, len, 0);
    uint8_t *pkt_pos = (uint8_t*)pkt->hdr + reply_len;
    if (blockwise) {
        pkt_pos += coap_opt_put_block1_control(pkt_pos, 0, &block1);
    }
    if (result_len) {
        *pkt_pos++ = 0xFF;
        pkt_pos += fmt_bytes_hex((char *)pkt_pos, digest, sizeof(digest));
    }

    return pkt_pos - (uint8_t*)pkt->hdr;
}




//----------------------------------------------------------------------
//----------------------------------------------------------------------
//----------------------------------------------------------------------
//<---------------------------  MY CODE  ------------------------------>
//----------------------------------------------------------------------
//----------------------------------------------------------------------



//// getdiddocument() returns this document signed
    /*
        DID document
        "{
            \"attestation\": \"public_key we created\"
        }"


        --> we sign this with hardcoded private key

        change sign function from hardcoded to created keys
    */

// /** @brief   Convert hex string to base64 string
// * @param[in]   in_hex     Hex string
// * @param[out]  out_base64  Base64 string
// * @returns      size of base64 string
//  */
// size_t hex_to_base64(uint8_t* in_hex, char* out_base64) {
//     uint8_t toBytes[EDSIGN_PUBLIC_KEY_SIZE] = { 0 };
//     fmt_hex_bytes(toBytes, (char*)in_hex); // convert hex to bytes

//     size_t size;
//     base64_encode(toBytes, sizeof(toBytes), out_base64, &size); // convert bytes to base64

//     return size;
// }

/** @brief   Convert bytes to base64 string
* @param[in]   in_bytes     Bytes
* @param[in]  in_bytes_size  Size of bytes array
* @param[out]  out_base64  Base64 string
* @returns      size of base64 string
 */
size_t bytes_to_base64(uint8_t* in_bytes, size_t in_bytes_size, char* out_base64) {
    size_t size;

    base64_encode(in_bytes, in_bytes_size, out_base64, &size); // convert bytes to base64

    return size;
}

/** @brief   Convert base64 to bytes
* @param[in]   in_base64     Base64 string
* @param[out]  out_bytes  Bytes
* @returns      size of bytes array
 */
size_t base64_to_bytes(char* in_base64, uint8_t* out_bytes) {
    size_t size;

    base64_decode(in_base64, strlen(in_base64), out_bytes, &size); // convert bytes to base64

    return size;
}

/** @brief  Create public and private keys for DID
* @param COAP-PARAMETERS
* @returns "keys created" if success
*/
static ssize_t _create_keys_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;
    uint8_t secret_key[EDSIGN_SECRET_KEY_SIZE] = { 0 };
    uint8_t public_key[EDSIGN_PUBLIC_KEY_SIZE] = { 0 };

    printf("RUNNING KEY HANDLER\n");
    /* Create the new keypair */ // Ed25519
    random_bytes(secret_key, sizeof(secret_key));
    ed25519_prepare(secret_key);
    edsign_sec_to_pub(public_key, secret_key);

    /* Print the new keypair */ //Prints the hex to compare with base64
    puts("New keypair generated:");
    printf("  - Secret: ");
    for (uint8_t i = 0; i < EDSIGN_SECRET_KEY_SIZE; ++i) {
        printf("%02X", secret_key[i]);
    }

    printf("\n  - Public: ");
    for (uint8_t i = 0; i < EDSIGN_PUBLIC_KEY_SIZE; ++i) {
        printf("%02X", public_key[i]);
    }
    puts("");


    //TRYING bytes_to_base64 and base64_to_bytes functions

    // // convert public key to base64
    // char* public_key_base64 = malloc(EDSIGN_PUBLIC_KEY_SIZE * 2);
    // bytes_to_base64(public_key, EDSIGN_SECRET_KEY_SIZE, public_key_base64);
    // printf("\n\nBase64: %s with size %d\n\n", public_key_base64, strlen(public_key_base64));

    // //convert base64 to bytes
    // uint8_t public_key_BYTES[EDSIGN_SECRET_KEY_SIZE] = { 0 };
    // base64_to_bytes(public_key_base64, public_key_BYTES);
    // printf("Compare: %d\n",memcmp(public_key_BYTES, public_key, sizeof(public_key)));

    free(secret_key_base64);
    free(public_key_base64);
    secret_key_base64 = malloc(EDSIGN_SECRET_KEY_SIZE * 2);
    public_key_base64 = malloc(EDSIGN_PUBLIC_KEY_SIZE * 2);

    //SAVE KEYS TO BASE64
    bytes_to_base64(secret_key, EDSIGN_SECRET_KEY_SIZE, secret_key_base64);
    bytes_to_base64(public_key, EDSIGN_PUBLIC_KEY_SIZE, public_key_base64);
    printf("\nSecret key base64: %s\n", secret_key_base64);
    printf("\nPublic key base64: %s\n", public_key_base64);

    return coap_reply_simple(pkt, COAP_CODE_205, buf, len,
            COAP_FORMAT_TEXT, "keys created", 13);
}

/** @brief  Get public key of DID
* @param COAP-PARAMETERS
* @returns public key of DID
*/
static ssize_t _get_public_key_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;

    return coap_reply_simple(pkt, COAP_CODE_205, buf, len,
            COAP_FORMAT_TEXT, public_key_base64, strlen(public_key_base64));
}

// static ssize_t _get_public_key_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context) {

//     char* temperature = "temperature"; 
    
// }

/** @brief  Get public key of DID
* @param[in] message to sign
* @param[in] message_len length of message
* @param[in] secret_key secret key
* @param[in] public_key public key
* @returns message with signature as string ("message,signature")
*/
char* signMessageAndReturnResponse(uint8_t* message, uint16_t message_len, uint8_t* secret_key, uint8_t* public_key) { // USED IN SIGN HANDLER

    uint8_t signature[EDSIGN_SIGNATURE_SIZE];
    // secret_key_bytes & public_key_bytes are used to make hex string to bytes
    uint8_t secret_key_bytes[EDSIGN_SECRET_KEY_SIZE] = { 0 };
    uint8_t public_key_bytes[EDSIGN_PUBLIC_KEY_SIZE] = { 0 };

    //Turn keys from hex to bytes to be able to sign
    fmt_hex_bytes(secret_key_bytes, (char*)secret_key);
    fmt_hex_bytes(public_key_bytes, (char*)public_key);

    //Sign message
    edsign_sign(signature, public_key_bytes, secret_key_bytes, message, message_len);

    //CHECK WITH VERIFY IF SIGN WORKED
    // int aaaa = edsign_verify(signature, public_key_bytes, message, message_len);
    // printf("%d\n\n", aaaa);

    char signature_hex[EDSIGN_SIGNATURE_SIZE * 2 + 1] = { 0 };
    fmt_bytes_hex(signature_hex, signature, EDSIGN_SIGNATURE_SIZE);
    //printf("%s", signature_hex);

    //Create response with signature
    char *response = malloc(EDSIGN_SIGNATURE_SIZE * 2 + 1 + 1 + message_len); 
    memcpy(response, message, message_len);
    memcpy(response + message_len, ",", 1);
    memcpy(response + message_len + 1, signature_hex, EDSIGN_SIGNATURE_SIZE * 2 + 1);
    
    return response;
}

/** @brief  Sign message with hardcoded keys
* @param COAP-PARAMETERS
* @returns message with signature as string ("message,signature")
*/
static ssize_t ed25519_sign_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;

    char *response;
    // sign message with hardcoded keys
    response = signMessageAndReturnResponse(pkt->payload, pkt->payload_len, secret_key_hex_hardcoded, public_key_hex_hardcoded);
    printf("Response: %s\n", response);

    // send back message and signature
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len,
            COAP_FORMAT_TEXT, response, strlen(response));
}

/** @brief  Create DID Document
* @param COAP-PARAMETERS
* @returns DID Document as string
*/
char* createDidDocument(void) {
    char* did = malloc(100);
    strcat(did, "\"id\": \"did:self:");
    strncat(did, (char*)public_key_hex, EDSIGN_PUBLIC_KEY_SIZE * 2);
    strcat(did, "\"");

    char* didAttestation = malloc(100);
    strcat(didAttestation, "\"attestation\": \"");
    strncat(didAttestation, (char*)public_key_hex, EDSIGN_PUBLIC_KEY_SIZE * 2);
    strcat(didAttestation, "\"");


    char* didDocument = malloc(1000); 
    strcat(didDocument, "{");

    strcat(didDocument, did);
    strcat(didDocument, ", ");
    strcat(didDocument, didAttestation);

    strcat(didDocument, "}");
            
    return didDocument;
}

/** @brief  Get DID document
* @param COAP-PARAMETERS
* @returns DID document
*/
static ssize_t getDidDocument(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void) context;
    char* didDocument = createDidDocument();
    
    char* response = signMessageAndReturnResponse((uint8_t*)didDocument, strlen(didDocument), secret_key_hex, public_key_hex);
    printf("Response: %s\n", response);
    
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len+2048, //INCREASE BUFFER SIZE TO SEND BIGGER RESPONSE
            COAP_FORMAT_TEXT, response, strlen(response));
}

/* must be sorted by path (ASCII order) */
const coap_resource_t coap_resources[] = {
    COAP_WELL_KNOWN_CORE_DEFAULT_HANDLER,
    { "/echo/", COAP_GET | COAP_MATCH_SUBTREE, _echo_handler, NULL },
    { "/riot/board", COAP_GET, _riot_board_handler, NULL },
    { "/riot/createkeys", COAP_GET, _create_keys_handler, NULL }, //MINE
    { "/riot/did", COAP_GET, getDidDocument, NULL }, //MINE
    { "/riot/getpublickey", COAP_GET, _get_public_key_handler, NULL }, //MINE
    { "/riot/sign", COAP_POST, ed25519_sign_handler, NULL }, //MINE
    { "/riot/value", COAP_GET | COAP_PUT | COAP_POST, _riot_value_handler, NULL },
    { "/riot/ver", COAP_GET, _riot_block2_handler, NULL },
    { "/sha256", COAP_POST, _sha256_handler, NULL },
    //{ "/riot/temperature", COAP_POST, , NULL}
};

const unsigned coap_resources_numof = ARRAY_SIZE(coap_resources);
