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
static uint8_t* secret_key_bytes;
static uint8_t* public_key_bytes;
static char* secret_key_base64;
static char* public_key_base64;

/* hardcoded digital signature key pair */
// static char secret_key_base64_hardcoded[100] = "i7QBTYsKY69y2ISCwSdszQMuJvwFgGiGqfGnJyEPT8M=";
// static char public_key_base64_hardcoded[100] = "0E6QcZJHHGA+FI1z1qOJeXbcJgEGqhIIN+vPgV8ERcI=";

static ssize_t _riot_board_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len,
            COAP_FORMAT_TEXT, (uint8_t*)RIOT_BOARD, strlen(RIOT_BOARD));
}

//// getdiddocument() returns this document signed
    /*
        DID document
        "{
            \"attestation\": \"public_key we created\"
        }"


        --> we sign this with hardcoded private key

        change sign function from hardcoded to created keys
    */

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

/** @brief   Hash string with SHA256
 * @param[in]   str     String to hash
 * @param[out]  hash    Hash of str
 * returns 0 on success
 */
int hash_string(char *str, char *hash)
{
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_context_t sha256;

    sha256_init(&sha256);
    sha256_update(&sha256, (uint8_t*)str, strlen(str));
    sha256_final(&sha256, digest);

    fmt_bytes_hex(hash, digest, sizeof(digest));

    return 0;
}

/** @brief  Create public and private keys for DID
* @param COAP-PARAMETERS
* @returns "keys created" if success
*/
/* -- COAP REQUEST --
REQUEST: coap-client -m get coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/createkeys
RESPONSE: keys created
*/
/* -- PRINT AT DEVICE CONSOLE --
New keypair generated(PRINT IN HEX TO VERIFY WITH BASE64):
  - Secret key hex: 4881E2BA00000000000000000000000000000000000000000000000000000040
  - Public key hex: 62FF3DADE2EFDA7C53D38F6005DF358946E22402E5CCDF2EBAC179E249F159FF
  - Secret key base64: SIHiugAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEA=
  - Public key base64: Yv89reLv2nxT049gBd81iUbiJALlzN8uusF54knxWf8=

  //PRINT HEX AS WELL FOR DEBUGGING
*/
static ssize_t _create_keys_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;
    secret_key_bytes = malloc(EDSIGN_SECRET_KEY_SIZE);
    public_key_bytes = malloc(EDSIGN_PUBLIC_KEY_SIZE);

    printf("RUNNING KEY HANDLER\n");
    /* Create the new keypair */ // Ed25519
    random_bytes(secret_key_bytes, sizeof(secret_key_bytes));
    ed25519_prepare(secret_key_bytes);
    edsign_sec_to_pub(public_key_bytes, secret_key_bytes);

    /* Print the new keypair */ //Prints the hex to compare with base64
    puts("New keypair generated(PRINT IN HEX TO VERIFY WITH BASE64):");
    printf("  - Secret key hex: ");
    for (uint8_t i = 0; i < EDSIGN_SECRET_KEY_SIZE; ++i)
        printf("%02X", secret_key_bytes[i]);

    printf("\n  - Public key hex: ");
    for (uint8_t i = 0; i < EDSIGN_PUBLIC_KEY_SIZE; ++i)
        printf("%02X", public_key_bytes[i]);
    puts("");


    free(secret_key_base64);
    free(public_key_base64);
    secret_key_base64 = malloc(EDSIGN_SECRET_KEY_SIZE * 2);
    public_key_base64 = malloc(EDSIGN_PUBLIC_KEY_SIZE * 2);

    //SAVE KEYS TO BASE64
    bytes_to_base64(secret_key_bytes, EDSIGN_SECRET_KEY_SIZE, secret_key_base64);
    bytes_to_base64(public_key_bytes, EDSIGN_PUBLIC_KEY_SIZE, public_key_base64);
    printf("  - Secret key base64: %s\n", secret_key_base64);
    printf("  - Public key base64: %s\n", public_key_base64);

    return coap_reply_simple(pkt, COAP_CODE_205, buf, len,
            COAP_FORMAT_TEXT, "keys created", 13);
}

/** @brief  Get public key of DID
* @param COAP-PARAMETERS
* @returns public key of DID
*/
/* -- COAP REQUEST --
REQUEST: coap-client -m get coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/getpublickey
RESPONSE: Yv89reLv2nxT049gBd81iUbiJALlzN8uusF54knxWf8= (SAME AS PRINTED IN DEVICE CONSOLE AT CREATEKEYS)
*/
/* -- PRINT AT DEVICE CONSOLE --
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
char* signMessageAndReturnResponse(uint8_t* message, uint16_t message_len, uint8_t* secret_key, uint8_t* public_key) // USED IN SIGN HANDLER
{ 
    uint8_t* signature = malloc(EDSIGN_SIGNATURE_SIZE);

    //Sign message
    edsign_sign(signature, public_key, secret_key, message, message_len);

    //CHECK WITH VERIFY IF SIGN WORKED (MUST BE NOT 0)
    int verify = edsign_verify(signature, public_key, message, message_len);
    if (verify == 0)
        printf("SIGNATURE NOT VERIFIED\n");
    else
        printf("SIGNATURE VERIFIED\n");

    //Turn signature to base64 string
    char* signature_base64 = malloc(EDSIGN_SIGNATURE_SIZE * 2);
    size_t size = bytes_to_base64(signature, EDSIGN_SIGNATURE_SIZE, signature_base64);

    //Create response with signature
    char *response = malloc(size + 1 + message_len); 
    memcpy(response, message, message_len);
    memcpy(response + message_len, ",", 1);
    memcpy(response + message_len + 1, signature_base64, size);

    free(signature);
    free(signature_base64);
    
    return response;
}

/** @brief  Sign message with hardcoded keys
* @param COAP-PARAMETERS
* @returns message with signature as string ("message,signature")
*/
/* -- COAP REQUEST --
REQUEST: coap-client -m post coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/sign -e message
RESPONSE: message,/bbM2225+nZeRJ6aA6xmGJdM2Bbc3qFNXpBjzdK8l8PiQGgiqDLHMRuIZO9ZF6qksvo7yvZOBKd9nuCDSgeaBg==
*/
/* -- PRINT AT DEVICE CONSOLE --
SIGNATURE VERIFIED

Response: message,/bbM2225+nZeRJ6aA6xmGJdM2Bbc3qFNXpBjzdK8l8PiQGgiqDLHMRuIZO9ZF6qksvo7yvZOBKd9nuCDSgeaBg==

//TESTING SIGN MESSAGE AND RETURN MESSAGE WITH SIGNATURE SEPARATED BY COMMA
*/
static ssize_t ed25519_sign_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;

    char *response;
    // sign message with hardcoded keys
    response = signMessageAndReturnResponse(pkt->payload, pkt->payload_len, secret_key_bytes, public_key_bytes);
    printf("\nResponse: %s\n", response);

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
    strncat(did, public_key_base64, strlen(public_key_base64));
    strcat(did, "\"");

    char* didAttestation = malloc(100);
    strcat(didAttestation, "\"attestation\": \"");
    strncat(didAttestation, public_key_base64, strlen(public_key_base64));
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
/* -- COAP REQUEST --
REQUEST: coap-client -m get coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/did
RESPONSE: {"id": "did:self:Yv89reLv2nxT049gBd81iUbiJALlzN8uusF54knxWf8=", "attestation": "Yv89reLv2nxT049gBd81iUbiJALlzN8uusF54knxWf8="},Xq2loWtdtJ3dmw5ZercJutIE+fD9RYHpEWuiB9iVYHQCscGYDSorgeUCvMpiSwXD1Ao0z+/Cs5iqYoiNFTWRDw==
*/
/* -- PRINT AT DEVICE CONSOLE --
SIGNATURE VERIFIED
Response: {"id": "did:self:Yv89reLv2nxT049gBd81iUbiJALlzN8uusF54knxWf8=", "attestation": "Yv89reLv2nxT049gBd81iUbiJALlzN8uusF54knxWf8="},Xq2loWtdtJ3dmw5ZercJutIE+fD9RYHpEWuiB9iVYHQCscGYDSorgeUCvMpiSwXD1Ao0z+/Cs5iqYoiNFTWRDw==

//DID STILL NOT IMPLEMENTED CORRECTLY
*/
static ssize_t getDidDocument(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void) context;
    char* didDocument = createDidDocument();
    
    char* response = signMessageAndReturnResponse((uint8_t*)didDocument, strlen(didDocument), secret_key_bytes, public_key_bytes);
    printf("Response: %s\n", response);
    
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len+2048, //INCREASE BUFFER SIZE TO SEND BIGGER RESPONSE
            COAP_FORMAT_TEXT, response, strlen(response));
}

/* must be sorted by path (ASCII order) */
const coap_resource_t coap_resources[] = {
    COAP_WELL_KNOWN_CORE_DEFAULT_HANDLER,
    { "/riot/board", COAP_GET, _riot_board_handler, NULL },
    { "/riot/createkeys", COAP_GET, _create_keys_handler, NULL }, //MINE
    { "/riot/did", COAP_GET, getDidDocument, NULL }, //MINE
    { "/riot/getpublickey", COAP_GET, _get_public_key_handler, NULL }, //MINE
    { "/riot/sign", COAP_POST, ed25519_sign_handler, NULL }, //MINE
};

const unsigned coap_resources_numof = ARRAY_SIZE(coap_resources);
