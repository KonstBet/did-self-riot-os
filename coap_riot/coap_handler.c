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
    char* signature;
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
    char* signature;
} did_document;

//DID ALL INFORMATION -------------------------------------------
typedef struct {
    did_document* document;
    did_proof* proof;
} did;
// ----------------------------------------------------------------

//----------------------------------------------------------------
static did* deviceDid = NULL; //DEVICE DID
//----------------------------------------------------------------
//----------------------------------------------------------------

// ----------------------------------------------------------------

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
 * @returns returns bytes of hash
 */
uint8_t* hashSH256(char *str)
{
    uint8_t* digest = calloc(SHA256_DIGEST_LENGTH, sizeof(uint8_t));
    sha256(str, strlen(str), digest);
    
    char* hash = calloc(SHA256_DIGEST_LENGTH*2, sizeof(char));
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(hash + (i * 2), "%02x", digest[i]);
    }
    printf("\nHash: %s\n", hash);

    return digest;
}
//----------------------------------------------------------------

typedef struct {
    uint8_t* secret_key_bytes;
    uint8_t* public_key_bytes;
    char* secret_key_base64;
    char* public_key_base64;
} key_pair;

/* digital signature key pair PROOF JWK*/ /* Generated using ed25519-genkeypair */
static key_pair* proof_key_pair = NULL;


/* digital signature key pair DID DOCUMENT JWK*/ /* Generated using ed25519-genkeypair */
static key_pair* document_key_pair = NULL;

//----------------------------------------------------------------

/** @brief  Sign message with private key
* @param[in] message to sign
* @param[in] message_len length of message
* @param[in] secret_key secret key
* @param[in] public_key public key
* @returns signature of message in base64
*/
char* sign_message(uint8_t* message, uint16_t message_len, uint8_t* secret_key, uint8_t* public_key) {
    uint8_t* signature = calloc(EDSIGN_SIGNATURE_SIZE, sizeof(uint8_t));

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
    bytes_to_base64url(signature, EDSIGN_SIGNATURE_SIZE, signature_base64);

    free(signature);

    return signature_base64;
}
//----------------------------------------------------------------

// STRUCTS TO STRING FOR JSON ------------------------------------

char* jwkToString(jwk* jwk){
    char* jwk_str = calloc(200, sizeof(char));
    sprintf(jwk_str, "{\"kty\":\"%s\",\"crv\":\"%s\",\"x\":\"%s\"}", jwk->kty, jwk->crv, jwk->x);
    return jwk_str;
}

char* jwkToStringLexicographically(jwk* jwk){ //LEXYCOGRAPHICALLY ORDERED FOR THUMPRINT OF JWK
    char* jwk_str = calloc(200, sizeof(char));
    sprintf(jwk_str, "{\"crv\":\"%s\",\"kty\":\"%s\",\"x\":\"%s\"}", jwk->crv, jwk->kty, jwk->x);
    return jwk_str;
}

char* didProofHeaderToString(did_proof_header* header){
    char* header_str = calloc(300, sizeof(char));
    sprintf(header_str, "{\"alg\":\"%s\",\"jwk\":%s}", header->alg, jwkToString(header->jwk));
    return header_str;
}

char* didProofPayloadToString(did_proof_payload* payload){
    char* payload_str = calloc(300, sizeof(char));
    sprintf(payload_str, "{\"iat\":%s,\"exp\":%s,\"s256\":\"%s\"}", payload->iat, payload->exp, payload->s256);
    return payload_str;
}

char* didProofHeaderAndPayloadToString(did_proof* proof){
    char* proof_str = calloc(600, sizeof(char));
    sprintf(proof_str, "{\"header\":%s,\"payload\":%s", didProofHeaderToString(proof->header), didProofPayloadToString(proof->payload));
    return proof_str;
}

char* didProofHeaderAndPayloadToStringAsBase64url(did_proof* proof){
    char* proof_str_base64 = calloc(600, sizeof(char));

    char* header = calloc(300, sizeof(char));
    bytes_to_base64url(didProofHeaderToString(proof->header), strlen(didProofHeaderToString(proof->header)), header);

    char* payload = calloc(300, sizeof(char));
    bytes_to_base64url(didProofPayloadToString(proof->payload), strlen(didProofPayloadToString(proof->payload)), payload);

    sprintf(proof_str_base64, "%s.%s", header, payload);
    return proof_str_base64;
}

char* didProofToString(did_proof* proof){
    char* proof_str = calloc(600, sizeof(char));
    sprintf(proof_str, "{\"header\":%s,\"payload\":%s,\"signature\":\"%s\"}", didProofHeaderToString(proof->header), didProofPayloadToString(proof->payload), proof->signature);
    return proof_str;
}

char* didProofToStringAsBase64url(did_proof* proof){
    char* proof_str_base64 = calloc(600, sizeof(char));

    char* header = calloc(300, sizeof(char));
    bytes_to_base64url(didProofHeaderToString(proof->header), strlen(didProofHeaderToString(proof->header)), header);

    char* payload = calloc(300, sizeof(char));
    bytes_to_base64url(didProofPayloadToString(proof->payload), strlen(didProofPayloadToString(proof->payload)), payload);

    sprintf(proof_str_base64, "%s.%s.%s", header, payload, proof->signature);
    return proof_str_base64;
}

char* attestationToString(attestation* attestation){
    char* attestation_str = calloc(300, sizeof(char));
    sprintf(attestation_str, "{\"id\":\"%s\",\"type\":\"%s\",\"publicKeyJwk\":%s}", attestation->id, attestation->type, jwkToString(attestation->publicKeyJwk));
    return attestation_str;
}

char* didDocumentToString(did_document* document){
    char* document_str = calloc(300, sizeof(char));
    sprintf(document_str, "{\"id\":\"%s\",\"attestation\":%s,\"signature\":\"%s\"}", document->id, attestationToString(document->attestation), document->signature);
    return document_str;
}

char* didDocumentToStringNoSignature(did_document* document){
    char* document_str = calloc(300, sizeof(char));
    sprintf(document_str, "{\"id\":\"%s\",\"attestation\":%s}", document->id, attestationToString(document->attestation));
    return document_str;
}

char* didDocumentToStringAsBase64urlNoSignature(did_document* document){
    char* document_str = calloc(300, sizeof(char));
    sprintf(document_str, "{\"id\":\"%s\",\"attestation\":%s}", document->id, attestationToString(document->attestation));
    char* document_str_base64 = calloc(300, sizeof(char));
    bytes_to_base64url(document_str, strlen(document_str), document_str_base64);
    
    return document_str_base64;
}

char* didDocumentToStringAsBase64url(did_document* document){
    char* document_base64 = calloc(500, sizeof(char));

    char* document_str = calloc(300, sizeof(char));
    sprintf(document_str, "{\"id\":\"%s\",\"attestation\":%s}", document->id, attestationToString(document->attestation));
    char* document_str_base64 = calloc(300, sizeof(char));
    bytes_to_base64url(document_str, strlen(document_str), document_str_base64);

    sprintf(document_base64, "%s.%s", document_str_base64, document->signature);
    
    return document_base64;
}

char* didToString(did* deviceDID){
    char* did_str = calloc(900, sizeof(char));
    sprintf(did_str, "{\"document\":%s,\"proof\":%s}", didDocumentToString(deviceDID->document), didProofToString(deviceDID->proof));
    return did_str;
}

char* didToStringAsBase64(did* deviceDID){
    char* did_str_base64 = calloc(900, sizeof(char));

    sprintf(did_str_base64, "%s %s", didDocumentToStringAsBase64url(deviceDID->document), didProofToStringAsBase64url(deviceDID->proof));
    return did_str_base64;
}
//----------------------------------------------------------------

// CREATE DID INFO
jwk* createJwk(char* kty, char* crv, char* x){
    jwk* jwk = calloc(1, sizeof(jwk));
    jwk->kty = kty;
    jwk->crv = crv;
    jwk->x = x;
    return jwk;
}

did_proof_header* createDidProofHeader(char* alg, jwk* jwk){
    did_proof_header* header = calloc(1, sizeof(did_proof_header));
    header->alg = alg;
    header->jwk = jwk;
    return header;
}

did_proof_payload* createDidProofPayload(char* iat, char* exp, char* s256){
    did_proof_payload* payload = calloc(1, sizeof(did_proof_payload));
    payload->iat = iat;
    payload->exp = exp;
    payload->s256 = s256;
    return payload;
}

did_proof* createDidProof(did_proof_header* header, did_proof_payload* payload){
    did_proof* proof = calloc(1, sizeof(did_proof));
    proof->header = header;
    proof->payload = payload;

    char* msg = didProofHeaderAndPayloadToStringAsBase64url(proof);
    printf("\n\naaa\n%s\n\n", msg);
    char *signature_base64 = sign_message((uint8_t*) msg, strlen(msg), proof_key_pair->secret_key_bytes, proof_key_pair->public_key_bytes);
    proof->signature = signature_base64;
    
    return proof;
}

attestation* createAttestation(char* id, char* type, jwk* publicKeyJwk){
    attestation* attestation = calloc(1, sizeof(attestation));
    attestation->id = id;
    attestation->type = type;
    attestation->publicKeyJwk = publicKeyJwk;
    return attestation;
}

did_document* createDidDocument(char* id, attestation* attestation){
    did_document* document = calloc(1, sizeof(did_document));
    document->id = id;
    document->attestation = attestation;

    char* msg = didDocumentToStringAsBase64urlNoSignature(document);
    printf("\n\nbbb\n%s\n\n", msg);
    char *signature_base64 = sign_message((uint8_t*) msg, strlen(msg), proof_key_pair->secret_key_bytes, proof_key_pair->public_key_bytes);
    document->signature = signature_base64;
    
    return document;
}

did* createDid(did_document* document, did_proof* proof){
    did* deviceDID = calloc(1, sizeof(did));
    deviceDID->document = document;
    deviceDID->proof = proof;
    return deviceDID;
}
//----------------------------------------------------------------

//DELETE & FREE MEMORY
void deleteDid(did* deviceDID){
    if (deviceDID != NULL) {
        // free(deviceDID->proof->header->alg);
        // free(deviceDID->proof->header->jwk->kty);
        // free(deviceDID->proof->header->jwk->crv);
        // free(deviceDID->proof->header->jwk);
        // free(deviceDID->proof->header);
        // free(deviceDID->proof->payload->iat);
        // free(deviceDID->proof->payload->exp);
        // free(deviceDID->proof->payload->s256);
        // free(deviceDID->proof->payload);
        // free(deviceDID->proof->signature);
        // free(deviceDID->proof);
        // free(deviceDID->document->id);
        // free(deviceDID->document->attestation->id);
        // free(deviceDID->document->attestation->type);
        // free(deviceDID->document->attestation->publicKeyJwk->kty);
        // free(deviceDID->document->attestation->publicKeyJwk->crv);
        // free(deviceDID->document->attestation->publicKeyJwk);
        // free(deviceDID->document->attestation);
        // free(deviceDID->document->signature);
        // free(deviceDID->document);
        // free(deviceDID);
        deviceDID = NULL;
    }
}

void deleteKeyPair(key_pair* keyPair) {
    if (keyPair != NULL) {
        free(keyPair->secret_key_bytes);
        free(keyPair->public_key_bytes);
        free(keyPair->secret_key_base64);
        free(keyPair->public_key_base64);
        free(keyPair);
        keyPair = NULL;
    }
}

//----------------------------------------------------------------

static ssize_t _riot_board_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, coap_request_ctx_t *context)
{
    (void)context;
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len,
            COAP_FORMAT_TEXT, (uint8_t*)RIOT_BOARD, strlen(RIOT_BOARD));
}


/** @brief  Create Public/Private Key Pair
 *  @param  keyPair: pointer to key_pair struct to store keys
 */
void createKeysEd25519(key_pair* keyPair){

    if (keyPair->secret_key_bytes == NULL) {
        keyPair->secret_key_bytes = calloc(EDSIGN_SECRET_KEY_SIZE, sizeof(uint8_t));
        keyPair->public_key_bytes = calloc(EDSIGN_PUBLIC_KEY_SIZE, sizeof(uint8_t));

        random_bytes(keyPair->secret_key_bytes, sizeof(keyPair->secret_key_bytes));
    }
    else {
        keyPair->public_key_bytes = calloc(EDSIGN_PUBLIC_KEY_SIZE, sizeof(uint8_t));
    }
    
    ed25519_prepare(keyPair->secret_key_bytes);
    edsign_sec_to_pub(keyPair->public_key_bytes, keyPair->secret_key_bytes);

    /* Print the new keypair */ //Prints the hex to compare with base64
    puts("New keypair generated(PRINT IN HEX TO VERIFY WITH BASE64):");
    printf("  - Secret key hex: ");
    for (uint8_t i = 0; i < EDSIGN_SECRET_KEY_SIZE; ++i)
        printf("%02X", keyPair->secret_key_bytes[i]);
    printf("\n  - Public key hex: ");
    for (uint8_t i = 0; i < EDSIGN_PUBLIC_KEY_SIZE; ++i)
        printf("%02X", keyPair->public_key_bytes[i]);
    puts("");

    
    //SAVE KEYS TO BASE64
    keyPair->public_key_base64 = calloc(100, sizeof(char));
    bytes_to_base64url(keyPair->public_key_bytes, EDSIGN_PUBLIC_KEY_SIZE, keyPair->public_key_base64);

    keyPair->secret_key_base64 = calloc(100, sizeof(char));
    bytes_to_base64url(keyPair->secret_key_bytes, EDSIGN_SECRET_KEY_SIZE, keyPair->secret_key_base64);

    printf("  - Secret key base64: %s\n", keyPair->secret_key_base64);
    printf("  - Public key base64: %s\n", keyPair->public_key_base64);
}

// // /* -- COAP REQUEST --
// // REQUEST: coap-client -m get coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/getpublickey
// // RESPONSE: Yv89reLv2nxT049gBd81iUbiJALlzN8uusF54knxWf8= (SAME AS PRINTED IN DEVICE CONSOLE AT CREATEKEYS)
// // */
// /** @brief  Get public key of DID Document
// * @param COAP-PARAMETERS
// * @returns public key of DID
// */
// static ssize_t _get_public_key_handler(coap_pkt_t *pkt, uint8_t *buf, size_t len, coap_request_ctx_t *context)
// {
//     (void)context;

//     if (proof_key_pair == NULL || proof_key_pair->public_key_base64 == NULL) {
//         char msg[] = "No Public Key found for DID Document Verification";
//         return coap_reply_simple(pkt, COAP_CODE_205, buf, len,
//             COAP_FORMAT_TEXT, msg, strlen(msg));
//     }
//     else
//         return coap_reply_simple(pkt, COAP_CODE_205, buf, len,
//             COAP_FORMAT_TEXT, proof_key_pair->public_key_base64, strlen(proof_key_pair->public_key_base64));
// }


/** @brief  Sign message with secret key and return nessage_base64.signature
* @param[in] message to sign
* @param[in] message_len length of message
* @param[in] secret_key secret key
* @param[in] public_key public key
* @returns message with signature as string => "message,signature"
*/
char* signMessageAndReturnMessageWithSignature(uint8_t* message, uint16_t message_len, uint8_t* secret_key, uint8_t* public_key) // USED IN SIGN HANDLER
{ 

    char *signature_base64 = sign_message(message, message_len, secret_key, public_key);

    //Create response with signature
    char *response = calloc(strlen(signature_base64) + 1 + message_len, sizeof(char));
    memcpy(response, message, message_len);
    memcpy(response + message_len, ".", 1);
    memcpy(response + message_len + 1, signature_base64, strlen(signature_base64));

    free(signature_base64);
    
    return response;
}

char* getTemperatureExample(void) {
    char *temperature = calloc(32, sizeof(char));
    memcpy(temperature, "{\"temperature\":25,\"scale\":\"C\"}", 31);

    char* temperature_base64 = calloc(50, sizeof(char));
    bytes_to_base64url(temperature, strlen(temperature), temperature_base64);

    return temperature_base64;
}

// /* -- COAP REQUEST --
// REQUEST: coap-client -m post coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/sign -e message
// RESPONSE: message,/bbM2225+nZeRJ6aA6xmGJdM2Bbc3qFNXpBjzdK8l8PiQGgiqDLHMRuIZO9ZF6qksvo7yvZOBKd9nuCDSgeaBg==
// */
/** @brief  Sign message with hardcoded keys
* @param COAP-PARAMETERS
* @returns message with signature as string ("message,signature")
*/
static ssize_t sendDataVerifiableWithDid(coap_pkt_t *pkt, uint8_t *buf, size_t len, coap_request_ctx_t *context)
{
    (void)context;
    char *data = getTemperatureExample();

    char *dataSigned = signMessageAndReturnMessageWithSignature((uint8_t *)data, strlen(data), document_key_pair->secret_key_bytes, document_key_pair->public_key_bytes);

    char *did_base64 = didToStringAsBase64(deviceDid);

    char *response = calloc(strlen(dataSigned) + 1 + strlen(did_base64), sizeof(char));
    memcpy(response, did_base64, strlen(did_base64));
    memcpy(response + strlen(did_base64), " ", 1);
    memcpy(response + strlen(did_base64) + 1, dataSigned, strlen(dataSigned));

    printf("\nResponse: %s\n", response);

    //send back message and signature
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len+1024,
            COAP_FORMAT_TEXT, response, strlen(response));
}

/** @brief  Creates a DID including DID Document and Proof
* @return Saves Result in deviceDid global variable and returns it
*/
did* createDeviceDid(void)
{
    deleteKeyPair(proof_key_pair);
    deleteKeyPair(document_key_pair);
    deleteDid(deviceDid);

    proof_key_pair = calloc(1, sizeof(key_pair));
    createKeysEd25519(proof_key_pair);
    document_key_pair = calloc(1, sizeof(key_pair));
    createKeysEd25519(document_key_pair);

    //CREATE PROOF KEY
    char* okp = calloc(3, sizeof(char));
    memcpy(okp, "OKP", 3);
    char* crv = calloc(7, sizeof(char));
    memcpy(crv, "Ed25519", 7);

    jwk* myProofJwk = createJwk(okp, crv, proof_key_pair->public_key_base64);
    printf("%s\n", jwkToString(myProofJwk));


    //CREATE PROOF HEADER
    char* alg = calloc(5, sizeof(char));
    memcpy(alg, "EdDSA", 5);

    did_proof_header* myDidProofHeader = createDidProofHeader(alg, myProofJwk);
    printf("%s\n", didProofHeaderToString(myDidProofHeader));


    //CREATE ATTESTATION
    char* attestationID = calloc(5, sizeof(char));
    memcpy(attestationID, "#key1", 5);
    char* attestationType = calloc(15, sizeof(char));
    memcpy(attestationType, "JsonWebKey2020", 15);

    char* okp2 = calloc(3, sizeof(char));
    memcpy(okp2, "OKP", 3);
    char* crv2 = calloc(7, sizeof(char));
    memcpy(crv2, "Ed25519", 7);

    jwk* myDocumentJwk = createJwk(okp2, crv2, document_key_pair->public_key_base64);
    printf("%s\n", jwkToString(myDocumentJwk));

    attestation* myattestation = createAttestation(attestationID, attestationType, myDocumentJwk);
    printf("%s\n", attestationToString(myattestation));


    //CREATE DID DOCUMENT
    char* id = calloc(100, sizeof(char));
    memcpy(id, "did:self:", 9);

    char* jwkHash = calloc(100, sizeof(char));
    uint8_t* digest = hashSH256(jwkToStringLexicographically(myProofJwk));
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
    digest = hashSH256(didDocumentToStringNoSignature(mydocument));
    bytes_to_base64url(digest, 32, s256);

    free(digest);

    did_proof_payload* myDidProofPayload = createDidProofPayload(iat_str, exp_str, s256);
    printf("%s\n", didProofPayloadToString(myDidProofPayload));

    
    //CREATE PROOF
    did_proof* myproof = createDidProof(myDidProofHeader, myDidProofPayload);
    printf("%s\n", didProofToString(myproof));


    //CREATE DID COMPLETE
    deviceDid = createDid(mydocument, myproof);
    printf("%s\n", didToString(deviceDid));

    return deviceDid;
}


// /* -- COAP REQUEST --
// REQUEST: coap-client -m get coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/did
// RESPONSE: 
// */
/** @brief  Get DID ALL INFORMATION
* @param COAP-PARAMETERS
* @returns DID ALL INFORMATION
*/
static ssize_t getDid(coap_pkt_t *pkt, uint8_t *buf, size_t len, coap_request_ctx_t *context)
{
    (void)context;
    if (deviceDid == NULL) {
        createDeviceDid();
    }
    // char* result = calloc(IPV6_ADDR_MAX_STR_LEN, sizeof(char));
    // ipv6_addr_to_str(result, context->remote->addr, IPV6_ADDR_MAX_STR_LEN);
    // printf("Target: %s\n", result);
    

    char* response = didToStringAsBase64(deviceDid);
    
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len+1024, //INCREASE BUFFER SIZE TO SEND BIGGER RESPONSE
            COAP_FORMAT_TEXT, response, strlen(response));
}

// /* -- COAP REQUEST --
// REQUEST: coap-client -m get coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/did/document
// RESPONSE: 
// */
/** @brief  Get DID document
* @param COAP-PARAMETERS
* @returns DID document
*/
static ssize_t getDidDocument(coap_pkt_t *pkt, uint8_t *buf, size_t len, coap_request_ctx_t *context)
{
    (void)context;
    if (deviceDid == NULL) {
        createDeviceDid();
    }

    char* response = didDocumentToString(deviceDid->document);
    
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len+1024, //INCREASE BUFFER SIZE TO SEND BIGGER RESPONSE
            COAP_FORMAT_TEXT, response, strlen(response));
}

// /* -- COAP REQUEST --
// REQUEST: coap-client -m get coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/did/proof
// RESPONSE: 
// */
/** @brief  Get DID Proof
* @param COAP-PARAMETERS
* @returns DID Proof
*/
static ssize_t getDidProof(coap_pkt_t *pkt, uint8_t *buf, size_t len, coap_request_ctx_t *context)
{
    (void)context;
    if (deviceDid == NULL) {
        createDeviceDid();
    }

    char* response = didProofToString(deviceDid->proof);
    
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len+1024, //INCREASE BUFFER SIZE TO SEND BIGGER RESPONSE
            COAP_FORMAT_TEXT, response, strlen(response));
}


// /* -- COAP REQUEST --
// REQUEST: coap-client -m put coap://[fe80::7cde:caff:fe7f:ca57%tap0]/riot/did
// RESPONSE: 
// */
/** @brief  Update DID
* @param COAP-PARAMETERS
* @returns "DID Updated" on success
*/
static ssize_t updateDid(coap_pkt_t *pkt, uint8_t *buf, size_t len, coap_request_ctx_t *context)
{
    (void)context;
    createDeviceDid();
    
    return coap_reply_simple(pkt, COAP_CODE_205, buf, len+1024, //INCREASE BUFFER SIZE TO SEND BIGGER RESPONSE
            COAP_FORMAT_TEXT, "DID Updated", 11);
}

/* must be sorted by path (ASCII order) */
const coap_resource_t coap_resources[] = {
    COAP_WELL_KNOWN_CORE_DEFAULT_HANDLER,
    { "/riot/board", COAP_GET, _riot_board_handler, NULL },
    { "/riot/did", COAP_GET, getDid, NULL }, //MINE
    { "/riot/did/document", COAP_GET, getDidDocument, NULL }, //MINE
    { "/riot/did/proof", COAP_GET, getDidProof, NULL }, //MINE
    { "/riot/data", COAP_GET, sendDataVerifiableWithDid, NULL }, //MINE
    { "/riot/did", COAP_PUT, updateDid, NULL }, //MINE
};

const unsigned coap_resources_numof = ARRAY_SIZE(coap_resources);
