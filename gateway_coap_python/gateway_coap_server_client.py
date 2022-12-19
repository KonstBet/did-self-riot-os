import datetime
import logging

import asyncio

from aiocoap import *

import aiocoap.resource as resource
import aiocoap
import json
import hashlib
import url64
import base64
from base64 import urlsafe_b64encode, urlsafe_b64decode
import jwt
from jwcrypto import jwk, jws

import ed25519

def base64UrlEncode(data):
    return urlsafe_b64encode(data).rstrip(b'=')


def base64UrlDecode(base64Url):
    padding = b'=' * (4 - (len(base64Url) % 4))

    return urlsafe_b64decode(base64Url + padding)


devices = { 'all': ['aaa'] }


class RiotBoard(resource.Resource):
    async def render_get(self, request):
        protocol = await Context.create_client_context()
        
        allResponses = []
        
        for device in devices['all']:

            request = Message(code=GET, uri='coap://[' + device + ']/riot/board')

            try:
                response = await protocol.request(request).response
            except Exception as e:
                print('Failed to fetch resource:')
                print(e)
            else:
                print('Result: %s\n%r'%(response.code, response.payload))
                
                allResponses.append(response.payload.decode('utf-8'))
                

        result = '[' + ','.join(allResponses) + ']'
        return aiocoap.Message(payload=result.encode('ascii'))
        
        
def verifyDiD(did):
    validDid = True #Return value
    
    result = did.split(" ")
            
    did_document_encoded = result[0].split(".")
    did_proof_encoded = result[1].split(".")
    
    did_document = base64UrlDecode(did_document_encoded[0].encode('utf-8'))
    did_document = json.loads(did_document)
    
    proof_header = base64UrlDecode(did_proof_encoded[0].encode('utf-8'))
    proof_header = json.loads(proof_header)
    
    proof_payload = base64UrlDecode(did_proof_encoded[1].encode('utf-8'))
    proof_payload = json.loads(proof_payload)
    
    print(did_document,"\n\n", proof_header, "\n\n", proof_payload, "\n\n")
    
    
    #------------------VERIFY SIGNATURE OF PROOF WITH HEADER JWK------------------
    #-----------------------------------------------------------------------------
    proof_public_key = base64UrlDecode(proof_header['jwk']['x'].encode('utf-8'))
    proof_public_key = base64.b64encode(proof_public_key)
    
    #PROOF JWK PUBLIC KEY
    verifyKey = ed25519.VerifyingKey(proof_public_key, encoding="base64")
    
    #SIGNATURE OF PROOF HEADER + PROOF PAYLOAD SPEPARATED BY A DOT
    signature = base64UrlDecode(did_proof_encoded[2].encode('utf-8'))
    signature = base64.b64encode(signature)
    
    #STRING OF PROOF HEADER + PROOF PAYLOAD SPEPARATED BY A DOT WHICH WE WANT TO VERIFY
    proof_string = did_proof_encoded[0] + "." + did_proof_encoded[1]
    proof_string = proof_string.encode('utf-8')
            
    try:
        verifyKey.verify(signature, proof_string, encoding="base64") #TODO SIGNATURE IS TOO BIG???
        print("Proof Signature is valid")
    except:
        print("Proof Signature is bad!")
        validDid = False
        
    #------------------VERIFY  EXP AND IAT------------------
    #-------------------------------------------------------
    try:
        decoded_jwt = jwt.decode(result[1], options={"verify_signature": False, "require": ["exp", "iat"], "verify_exp": True, "verify_iat": True, })
    except:
        validDid = False
    
    #------------------VERIFY THUMBPRINT EQUALS TO DID DOCUMENT ID------------------
    #-------------------------------------------------------------------------------
    
    m = hashlib.sha256()
    m.update(json.dumps(proof_header['jwk'], sort_keys=True, separators=(',', ':')).encode('utf-8'))
    thumbprint = m.digest()
    thumbprint = base64UrlEncode(thumbprint)
    
    didId = "did:self:" + thumbprint.decode('utf-8')
    if ( did_document['id'] != didId):
        raise Exception("The proof header contains invalid key")
        validDid = False
        return -1
    
    #------------------VERIFY S256 CONTAINS HASH OF DID DOCUMENT------------------
    #-----------------------------------------------------------------------------
    
    m = hashlib.sha256()
    m.update(json.dumps(did_document, separators=(',', ':')).encode('utf-8'))
    s256 = m.digest()
    s256 = base64UrlEncode(s256)
    
    if (proof_payload['s256'] != s256.decode('utf-8')):
        raise Exception("The proof payload contains invalid hash")
        validDid = False
        return -1
    
    
    return validDid
    
    
class getDid(resource.Resource):
    async def render_get(self, request):
        protocol = await Context.create_client_context()
        
        allResponses = []
        
        for device in devices['all']:

            request = Message(code=GET, uri='coap://[' + device + ']/riot/did')

            try:
                response = await protocol.request(request).response
            except Exception as e:
                print('Failed to fetch resource:')
                print(e)
            else:
                print('Result: %s\n%r\n\n'%(response.code, response.payload))
                
                validDid = verifyDiD(response.payload.decode('utf-8'))
                
                if validDid:
                    print("VALID DID")
                    allResponses.append(response.payload.decode('utf-8'))
                else:
                    print("INVALID DID FOR DEVICE: " + device)
                    
        if len(allResponses) == 0:
            return aiocoap.Message(payload="No valid DID found".encode('ascii'))
        else :
            result = '[' + ','.join(allResponses) + ']'
            return aiocoap.Message(payload=result.encode('ascii'))


def verifyData(response):
    validData = None #Return value
    
    result = response.split(" ")
    
    did_document_encoded = result[0].split(".")     
    data_encoded = result[2].split(".")
    
    did_document = base64UrlDecode(did_document_encoded[0].encode('utf-8'))
    did_document = json.loads(did_document)
    
    data = base64UrlDecode(data_encoded[0].encode('utf-8'))
    data = json.loads(data)
    
    print(did_document, "\n\n", data, "\n\n")
    
    
    #------------------VERIFY SIGNATURE OF DATA WITH DID DOCUMENT JWK------------------
    #----------------------------------------------------------------------------------
    did_document_public_key = base64UrlDecode(did_document['attestation']['publicKeyJwk']['x'].encode('utf-8'))
    did_document_public_key = base64.b64encode(did_document_public_key)
    
    #PROOF JWK PUBLIC KEY
    verifyKey = ed25519.VerifyingKey(did_document_public_key, encoding="base64")
    
    #SIGNATURE OF PROOF HEADER + PROOF PAYLOAD SPEPARATED BY A DOT
    signature = base64UrlDecode(data_encoded[1].encode('utf-8'))
    signature = base64.b64encode(signature)
    
    #STRING OF PROOF HEADER + PROOF PAYLOAD SPEPARATED BY A DOT WHICH WE WANT TO VERIFY
    data_string = data_encoded[0]
    data_string = data_string.encode('utf-8')
            
    try:
        verifyKey.verify(signature, data_string, encoding="base64") #TODO SIGNATURE IS TOO BIG???
        print("Data Signature is valid")
        validData = data
    except:
        print("Data Signature is bad!")
        
    return validData
    
    
    
class getData(resource.Resource):
    async def render_get(self, request):
        protocol = await Context.create_client_context()
        
        allResponses = []
        
        for device in devices['all']:

            request = Message(code=GET, uri='coap://[' + device + ']/riot/data')

            try:
                response = await protocol.request(request).response
            except Exception as e:
                print('Failed to fetch resource:')
                print(e)
            else:
                print('Result: %s\n%r\n\n'%(response.code, response.payload))
                
                # Validate DID
                validDid = verifyDiD(response.payload.decode('utf-8'))
                
                if validDid:
                    print("VALID DID")
                else:
                    print("INVALID DID FOR DEVICE: " + device)
                
                # Validate DATA
                validData = verifyData(response.payload.decode('utf-8'))
                
                if validData != None:
                    print("VALID DATA")
                    allResponses.append(json.dumps(validData, separators=(',', ':')))
                else:
                    print("INVALID DATA")
                
        if len(allResponses) == 0:
            return aiocoap.Message(payload="No valid DATA found".encode('ascii'))
        else :
            result = '[' + ','.join(allResponses) + ']'
            return aiocoap.Message(payload=result.encode('ascii'))



class wellknown(resource.Resource):
    async def render_get(self, request):
        protocol = await Context.create_client_context()
        
        allResponses = []
        
        for device in devices['all']:

            request = Message(code=GET, uri='coap://[' + device + ']/.well-known/core')

            try:
                response = await protocol.request(request).response
            except Exception as e:
                print('Failed to fetch resource:')
                print(e)
            else:
                print('Result: %s\n%r'%(response.code, response.payload))
                
                allResponses.append(response.payload.decode('utf-8'))
        
        if len(allResponses) == 0:
            return aiocoap.Message(payload="No Devices were found".encode('ascii'))
        else :
            result = ''.join(allResponses)
            return aiocoap.Message(payload=result.encode('ascii'))
        
        
class newDevice(resource.Resource):
    async def render_post(self, request):
        newDeviceJson = json.loads(request.payload.decode('utf-8'))
        
        devices['all'].append(newDeviceJson['ipv6']+'%'+newDeviceJson['interface'])
        print(devices)
        return aiocoap.Message(payload="success".encode('ascii'))
        
        
        

# logging setup

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)

async def main():
    # Resource tree creation
    root = resource.Site()

    root.add_resource(['.well-known', 'core'],
            resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['riot','board'], RiotBoard())
    root.add_resource(['riot','did'], getDid())
    root.add_resource(['riot','data'], getData())
    root.add_resource(['.well-known','core'], wellknown())
    root.add_resource(['newdevice'], newDevice())


    await aiocoap.Context.create_server_context(root)
    # Run forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())