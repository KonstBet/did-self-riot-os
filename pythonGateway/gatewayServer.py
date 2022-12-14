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


public_key = b"d04e907192471c603e148d73d6a3897976dc260106aa120837ebcf815f0445c2"
devices = { 'all': [] }

class BlockResource(resource.Resource):
    """Example resource which supports the GET and PUT methods. It sends large
    responses, which trigger blockwise transfer."""

    def __init__(self):
        super().__init__()
        self.set_content(b"This is the resource's default content. It is padded "
                b"with numbers to be large enough to trigger blockwise "
                b"transfer.\n")

    def set_content(self, content):
        self.content = content
        while len(self.content) <= 1024:
            self.content = self.content + b"0123456789\n"

    async def render_get(self, request):
        return aiocoap.Message(payload=self.content)

    async def render_put(self, request):
        print('PUT payload: %s' % request.payload)
        self.set_content(request.payload)
        return aiocoap.Message(code=aiocoap.CHANGED, payload=self.content)


class SeparateLargeResource(resource.Resource):
    """Example resource which supports the GET method. It uses asyncio.sleep to
    simulate a long-running operation, and thus forces the protocol to send
    empty ACK first. """

    def get_link_description(self):
        # Publish additional data in .well-known/core
        return dict(**super().get_link_description(), title="A large resource")

    async def render_get(self, request):
        await asyncio.sleep(3)

        payload = "Three rings for the elven kings under the sky, seven rings "\
                "for dwarven lords in their halls of stone, nine rings for "\
                "mortal men doomed to die, one ring for the dark lord on his "\
                "dark throne.".encode('ascii')
        return aiocoap.Message(payload=payload)

class TimeResource(resource.ObservableResource):
    """Example resource that can be observed. The `notify` method keeps
    scheduling itself, and calles `update_state` to trigger sending
    notifications."""

    def __init__(self):
        super().__init__()

        self.handle = None

    def notify(self):
        self.updated_state()
        self.reschedule()

    def reschedule(self):
        self.handle = asyncio.get_event_loop().call_later(5, self.notify)

    def update_observation_count(self, count):
        if count and self.handle is None:
            print("Starting the clock")
            self.reschedule()
        if count == 0 and self.handle:
            print("Stopping the clock")
            self.handle.cancel()
            self.handle = None

    async def render_get(self, request):
        payload = datetime.datetime.now().\
                strftime("%Y-%m-%d %H:%M").encode('ascii')
        return aiocoap.Message(payload=payload)

class WhoAmI(resource.Resource):
    async def render_get(self, request):
        text = ["Used protocol: %s." % request.remote.scheme]

        text.append("Request came from %s." % request.remote.hostinfo)
        text.append("The server address used %s." % request.remote.hostinfo_local)

        claims = list(request.remote.authenticated_claims)
        if claims:
            text.append("Authenticated claims of the client: %s." % ", ".join(repr(c) for c in claims))
        else:
            text.append("No claims authenticated.")

        return aiocoap.Message(content_format=0,
                payload="\n".join(text).encode('utf8'))


#coap://[fe80::8ef:85ff:fe1b:3fc%tap0]/riot/board
class RiotBoard(resource.Resource):
    async def render_get(self, request):
        protocol = await Context.create_client_context()
        
        for device in devices['all']:

            request = Message(code=GET, uri='coap://[' + device + ']/riot/board')

            print("GET ME THE BOARD FROM ")

            try:
                response = await protocol.request(request).response
            except Exception as e:
                print('Failed to fetch resource:')
                print(e)
            else:
                print('Result: %s\n%r'%(response.code, response.payload))
                

                return aiocoap.Message(payload=response.payload.decode('utf-8').encode('ascii'))

class create_ed25519Keys(resource.Resource):
    async def render_get(self, request):
        protocol = await Context.create_client_context()
        print("GETTING KEYS")

        request = Message(code=GET, uri='coap://[' + devices['all'][0] + ']/riot/createkeys')

        print("TAKE KEYS")

        try:
            response = await protocol.request(request).response
        except Exception as e:
            print('Failed to fetch resource:')
            print(e)
        else:
            print('Result: %s\n%r'%(response.code, response.payload))
            print(response.remote.hostinfo) #TODO TODO TODO TODO TODO
            
            return aiocoap.Message(payload=response.payload.decode('utf-8').encode('ascii'))

class getPublicKey(resource.Resource):
    async def render_get(self, request):
        protocol = await Context.create_client_context()
        print("GETTING KEYS")

        request = Message(code=GET, uri='coap://[' + devices['all'][0] + ']/riot/getpublickey')

        print("TAKE KEYS")

        try:
            response = await protocol.request(request).response
        except Exception as e:
            print('Failed to fetch resource:')
            print(e)
        else:
            print('Result: %s\n%r'%(response.code, response.payload))
            
            return aiocoap.Message(payload=response.payload.decode('utf-8').encode('ascii'))
        
def verifyDiD(did):
    result = did.split(" ")
    print(result)
            
    did_document_encoded = result[0].split(".")
    did_proof_encoded = result[1].split(".")
    print(did_document_encoded, did_proof_encoded, "\n\n")
    
    
    did_document = base64UrlDecode(did_document_encoded[0].encode('utf-8'))
    did_document = json.loads(did_document)
    
    proof_header = base64UrlDecode(did_proof_encoded[0].encode('utf-8'))
    proof_header = json.loads(proof_header)
    
    proof_payload = base64UrlDecode(did_proof_encoded[1].encode('utf-8'))
    proof_payload = json.loads(proof_payload)
    
    print(did_document,"\n\n", proof_header, "\n\n", proof_payload, "\n\n", proof_header['jwk']['x'], "\n\n")
    
    proof_public_key = base64UrlDecode(proof_header['jwk']['x'].encode('utf-8'))
    proof_public_key = base64.b64encode(proof_public_key)
    
    print(proof_public_key, "\n\n")
    
    #------------------VERIFY SIGNATURE OF PROOF WITH HEADER JWK------------------
    #PROOF JWK PUBLIC KEY
    verifyKey = ed25519.VerifyingKey(proof_public_key, encoding="base64")
    
    #SIGNATURE OF PROOF HEADER + PROOF PAYLOAD SPEPARATED BY A DOT
    signature = base64UrlDecode(did_proof_encoded[2].encode('utf-8'))
    signature = base64.b64encode(signature)
    
    print(signature, "\n\n")
    
    #STRING OF PROOF HEADER + PROOF PAYLOAD SPEPARATED BY A DOT WHICH WE WANT TO VERIFY
    proof_string = did_proof_encoded[0] + "." + did_proof_encoded[1]
    proof_string = proof_string.encode('utf-8')
    
    print(proof_string, "\n\n")
            
    try:
        verifyKey.verify(signature, proof_string, encoding="base64") #TODO SIGNATURE IS TOO BIG???
        print("Signature is valid")
    except:
        print("signature is bad!")
        
    #------------------VERIFY  EXP AND IAT------------------
    decoded_jwt = jwt.decode(result[1], options={"verify_signature": False, "require": ["exp", "iat"], "verify_exp": True, "verify_iat": True, })
    
    print(decoded_jwt, "\n\n")
    
    #------------------VERIFY THUMBPRINT EQUALS TO DID DOCUMENT ID------------------
    print(json.dumps(proof_header['jwk'], sort_keys=True), "\n\n")
    _jwk = jwk.JWK.from_json(json.dumps(proof_header['jwk'], sort_keys=True)) #<--Surround it try except
    _did = "did:self:" + _jwk.thumbprint()
    if ( did_document['id'] != did):
        raise Exception("The proof header contains invalid key")
        return -1
    
    
    

class getDid(resource.Resource):
    async def render_get(self, request):
        protocol = await Context.create_client_context()

        request = Message(code=GET, uri='coap://[' + devices['all'][0] + ']/riot/did')

        try:
            response = await protocol.request(request).response
        except Exception as e:
            print('Failed to fetch resource:')
            print(e)
        else:
            print('Result: %s\n%r\n\n'%(response.code, response.payload))
            
            verifyDiD(response.payload.decode('utf-8'))
            
            
            
            # did = json.loads(response.payload.decode('utf-8'))
            # print(did["document"]["id"])
            # verifyDiD(did)
            
            
            return aiocoap.Message(payload=response.payload.decode('utf-8').encode('ascii'))

class wellknown(resource.Resource):
    async def render_get(self, request):
        protocol = await Context.create_client_context()
        print("GETTING KEYS")

        request = Message(code=GET, uri='coap://[' + devices['all'][0] + ']/.well-known/core')

        print("TAKE KEYS")

        try:
            response = await protocol.request(request).response
        except Exception as e:
            print('Failed to fetch resource:')
            print(e)
        else:
            print('Result: %s\n%r'%(response.code, response.payload))
            
            return aiocoap.Message(payload=response.payload.decode('utf-8').encode('ascii'))
        
        
class newDevice(resource.Resource):
    async def render_post(self, request):
        print(request.remote.hostinfo)
        print(request.payload)
        newDeviceJson = json.loads(request.payload.decode('utf-8'))
        print(newDeviceJson)
        
        devices['all'].append(newDeviceJson['ipv6']+'%'+newDeviceJson['interface'])
        print(devices)
        return aiocoap.Message(payload="success".encode('ascii'))
        
        
class signAndVerify(resource.Resource):
    async def render_post(self, request):
        protocol = await Context.create_client_context()
        print(request.payload)

        request = Message(code=POST, uri='coap://[' + devices['all'][0] + ']/riot/sign', payload=request.payload)
        
        print("AAAAAAAAAA")
        print(request)
        try:
            response = await protocol.request(request).response
            
            print(response)
        except Exception as e:
            print('Failed to fetch resource:')
            print(e)
        else:
            print('Result: %s\n%r'%(response.code, response.payload))
            print
            
            result = response.payload.decode('utf-8').split(",")
            print(result)
            
            
            verifyKey = ed25519.VerifyingKey(public_key, encoding="hex")
            
            try:
                verifyKey.verify(result[1].encode('UTF-8'), result[0].encode('UTF-8'), encoding="hex") #TODO SIGNATURE IS TOO BIG???
                print("Signature is valid")
            except:
                print("signature is bad!")
            
            return aiocoap.Message(payload=response.payload.decode('utf-8').encode('ascii'))
        
        

# logging setup

logging.basicConfig(level=logging.INFO)
logging.getLogger("coap-server").setLevel(logging.DEBUG)

async def main():
    # Resource tree creation
    root = resource.Site()

    root.add_resource(['.well-known', 'core'],
            resource.WKCResource(root.get_resources_as_linkheader))
    root.add_resource(['time'], TimeResource())
    root.add_resource(['other', 'block'], BlockResource())
    root.add_resource(['other', 'separate'], SeparateLargeResource())
    root.add_resource(['whoami'], WhoAmI())

    root.add_resource(['riot','board'], RiotBoard())
    root.add_resource(['riot','createkeys'], create_ed25519Keys())
    root.add_resource(['riot','getpublickey'], getPublicKey())
    root.add_resource(['riot','did'], getDid())
    root.add_resource(['.well-known','core'], wellknown())
    root.add_resource(['newdevice'], newDevice())
    root.add_resource(['riot','signandverify'], signAndVerify())


    await aiocoap.Context.create_server_context(root)

    # Run forever
    await asyncio.get_running_loop().create_future()

if __name__ == "__main__":
    asyncio.run(main())