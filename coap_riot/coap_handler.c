#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "fmt.h"
#include "net/nanocoap.h"
#include "hashes/sha256.h"
#include "kernel_defines.h"

#include "edsign.h"
#include "ed25519.h"
#include "random.h"
#include "base64.h"

//DID PROOF -----------------------------------------------------
typedef struct {
    char* kty;
    char* crv;
    char* x;
} jwk;

typedef struct {
    char* alg;
    jwk* jwk;
} did_proof_header;

typedef struct {
    char* iat;
    char* exp;
    char* s256;
} did_proof_payload;

typedef struct {
    did_proof_header* header;
    did_proof_payload* payload;
} did_proof;

//DID DOCUMENT --------------------------------------------------
typedef struct {
    char* id;
    char* type;
    jwk* publicKeyJwk;
} attestation;

typedef struct {
    char* id;
    attestation* attestation;
} did_document;

//DID ALL INFORMATION -------------------------------------------
typedef struct {
    did_document* document;
    did_proof* proof;
} did;


/* digital signature key pair */ /* Generated using ed25519-genkeypair */
static uint8_t* secret_key_bytes;
static uint8_t* public_key_bytes;
static char* secret_key_base64;
static char* public_key_base64;

//----------------------------------------------------------------
static did* deviceDid = NULL; //DEVICE DID
//----------------------------------------------------------------

// CREATE DID INFO
jwk* createJwk(char* kty, char* crv, char* x){
    jwk* jwk = malloc(sizeof(jwk));
    jwk->kty = kty;
    jwk->crv = crv;
    jwk->x = x;
    return jwk;
}

did_proof_header* createDidProofHeader(char* alg, jwk* jwk){
    did_proof_header* header = malloc(sizeof(did_proof_header));
    header->alg = alg;
    header->jwk = jwk;
    return header;
}

did_proof_payload* createDidProofPayload(char* iat, char* exp, char* s256){
    did_proof_payload* payload = malloc(sizeof(did_proof_payload));
    payload->iat = iat;
    payload->exp = exp;
    payload->s256 = s256;
    return payload;
}

did_proof* createDidProof(did_proof_header* header, did_proof_payload* payload){
    did_proof* proof = malloc(sizeof(did_proof));
    proof->header = header;
    proof->payload = payload;
    return proof;
}

attestation* createAttestation(char* id, char* type, jwk* publicKeyJwk){
    attestation* attestation = malloc(sizeof(attestation));
    attestation->id = id;
    attestation->type = type;
    attestation->publicKeyJwk = publicKeyJwk;
    return attestation;
}

did_document* createDidDocument(char* id, attestation* attestation){
    did_document* document = malloc(sizeof(did_document));
    document->id = id;
    document->attestation = attestation;
    return document;
}

did* createDid(did_document* document, did_proof* proof){
    did* deviceDID = malloc(sizeof(did));
    deviceDID->document = document;
    deviceDID->proof = proof;
    return deviceDID;
}
//----------------------------------------------------------------

// STRUCTS TO STRING FOR JSON ------------------------------------

char* jwkToString(jwk* jwk){
    char* jwk_str = calloc(200, sizeof(char));
    sprintf(jwk_str, "{\"kty\":\"%s\",\"crv\":\"%s\",\"x\":\"%s\"}", jwk->kty, jwk->crv, jwk->x);
    return jwk_str;
}

char* didProofHeaderToString(did_proof_header* header){
    char* header_str = calloc(300, sizeof(char));
    sprintf(header_str, "{\"alg\":\"%s\",\"jwk\":%s}", header->alg, jwkToString(header->jwk));
    return header_str;
}

char* didProofPayloadToString(did_proof_payload* payload){
    char* payload_str = calloc(300, sizeof(char));
    sprintf(payload_str, "{\"iat\":\"%s\",\"exp\":\"%s\",\"s256\":\"%s\"}", payload->iat, payload->exp, payload->s256);
    return payload_str;
}

char* didProofToString(did_proof* proof){
    char* proof_str = calloc(600, sizeof(char));
    sprintf(proof_str, "{\"header\":%s,\"payload\":%s}", didProofHeaderToString(proof->header), didProofPayloadToString(proof->payload));
    return proof_str;
}

char* attestationToString(attestation* attestation){
    char* attestation_str = calloc(300, sizeof(char));
    sprintf(attestation_str, "{\"id\":\"%s\",\"type\":\"%s\",\"publicKeyJwk\":%s}", attestation->id, attestation->type, jwkToString(attestation->publicKeyJwk));
    return attestation_str;
}

char* didDocumentToString(did_document* document){
    char* document_str = calloc(300, sizeof(char));
    sprintf(document_str, "{\"id\":\"%s\",\"attestation\":%s}", document->id, attestationToString(document->attestation));
    return document_str;
}

char* didToString(did* deviceDID){
    char* did_str = calloc(900, sizeof(char));
    sprintf(did_str, "{\"document\":%s,\"proof\":%s}", didDocumentToString(deviceDID->document), didProofToString(deviceDID->proof));
    return did_str;
}
//----------------------------------------------------------------




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

/** @brief   Convert bytes to base64url
* @param[in]   in_bytes     Bytes
* @param[in]  in_bytes_size  Size of bytes array
* @param[out]  out_base64url  Base64 string
* @returns      size of base64 string
 */
size_t bytes_to_base64url(void* in_bytes, size_t in_bytes_size, void* out_base64url) {
    size_t size;

    base64url_encode(in_bytes, in_bytes_size, out_base64url, &size); // convert bytes to base64url

    return size;
}

/** @brief   Hash string with SHA256
 * @param[in]   str     String to hash
 * @param[out]  hash    Hash of str
 * @returns returns 0 on success
 */
uint8_t* hashSH256(char *str)
{
    uint8_t* digest = calloc(SHA256_DIGEST_LENGTH, sizeof(uint8_t));
    sha256(str, strlen(str), digest);
    
    // char* hash = calloc(SHA256_DIGEST_LENGTH*2, sizeof(char));
    // for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    //     sprintf(hash + (i * 2), "%02x", digest[i]);
    // }

    return digest;
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
    secret_key_bytes = calloc(EDSIGN_SECRET_KEY_SIZE, sizeof(uint8_t));
    public_key_bytes = calloc(EDSIGN_PUBLIC_KEY_SIZE, sizeof(uint8_t));

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

    //SAVE KEYS TO BASE64
    public_key_base64 = calloc(100, sizeof(char));
    bytes_to_base64url(public_key_bytes, EDSIGN_PUBLIC_KEY_SIZE, public_key_base64);

    secret_key_base64 = calloc(100, sizeof(char));
    bytes_to_base64url(secret_key_bytes, EDSIGN_SECRET_KEY_SIZE, secret_key_base64);
    
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
    char* signature_base64 = calloc(EDSIGN_SIGNATURE_SIZE * 2, sizeof(char));
    size_t size = bytes_to_base64url(signature, EDSIGN_SIGNATURE_SIZE, signature_base64);

    //Create response with signature
    char *response = calloc(size + 1 + message_len, sizeof(char));
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

void createDeviceDid(void)
{
    //CREATE KEY
    char* okp = calloc(3, sizeof(char));
    memcpy(okp, "OKP", 3);
    char* crv = calloc(7, sizeof(char));
    memcpy(crv, "Ed25519", 7);

    jwk* myjwk = createJwk(okp, crv, public_key_base64);
    printf("%s\n", jwkToString(myjwk));


    //CREATE PROOF HEADER
    char* alg = calloc(5, sizeof(char));
    memcpy(alg, "HS256", 5);

    did_proof_header* myDidProofHeader = createDidProofHeader(alg, myjwk);
    printf("%s\n", didProofHeaderToString(myDidProofHeader));


    //CREATE ATTESTATION
    char* attestationID = calloc(5, sizeof(char));
    memcpy(attestationID, "#key1", 5);
    char* attestationType = calloc(15, sizeof(char));
    memcpy(attestationType, "JsonWebKey2020", 15);

    attestation* myattestation = createAttestation(attestationID, attestationType, myjwk);
    printf("%s\n", attestationToString(myattestation));


    //CREATE DID DOCUMENT
    char* id = calloc(100, sizeof(char));
    memcpy(id, "did:self:", 9);

    char* jwkHash = calloc(100, sizeof(char));
    uint8_t* digest = hashSH256(jwkToString(myjwk));
    bytes_to_base64url(digest, 32, jwkHash);
    memcpy(id + 9, jwkHash, strlen(jwkHash));

    did_document* mydocument = createDidDocument(id, myattestation);
    printf("%s\n", didDocumentToString(mydocument));


    //CREATE PROOF PAYLOAD
    time_t now = time(NULL); // IAT
    if (now == -1)
        puts("The time() function failed");
        
    char* iat_str = calloc(10, sizeof(char));
    sprintf(iat_str, "%ld", now);

    struct tm* tm = localtime(&now);
    tm->tm_year = tm->tm_year + 1; // EXPIRE IN 1 YEAR
    time_t next = mktime(tm); // EXP
    char* exp_str = calloc(10, sizeof(char));
    sprintf(exp_str, "%ld", next);

    char* s256 = calloc(100, sizeof(char));
    digest = hashSH256(didDocumentToString(mydocument));
    bytes_to_base64url(digest, 32, s256);

    free(digest);

    did_proof_payload* myDidProofPayload = createDidProofPayload(iat_str, exp_str, s256);
    printf("%s\n", didProofPayloadToString(myDidProofPayload));

    
    //CREATE PROOF
    did_proof* myproof = createDidProof(myDidProofHeader, myDidProofPayload);
    printf("%s\n", didProofToString(myproof));


    //CREATE DID COMPLETE
    deviceDid = malloc(sizeof(did));
    deviceDid = createDid(mydocument, myproof);
    printf("%s\n", didToString(deviceDid));
}


/** @brief  Get DID document
* @param COAP-PARAMETERS
* @returns DID document
*/
/* -- COAP REQUEST --
REQUEST: coap-client -m get coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/did
RESPONSE: 
*/
/* -- PRINT AT DEVICE CONSOLE --

*/
static ssize_t getDidDocument(coap_pkt_t *pkt, uint8_t *buf, size_t len, void *context)
{
    (void)context;
    if (deviceDid == NULL) {
        printf("DID NOT CREATED\n");
        createDeviceDid();
    }

    char* response = didToString(deviceDid);
    
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
