import ed25519

privKey, pubKey = ed25519.create_keypair()
print("Private key (32 bytes):", privKey.to_ascii(encoding='hex'))
print("Public key (32 bytes): ", pubKey.to_ascii(encoding='hex'))

msg = b'Message for Ed25519 signing'
signature = privKey.sign(msg, encoding='hex')
print("Signature (64 bytes):", signature)

try:
    pubKey.verify(signature, msg, encoding='hex')
    print("The signature is valid.")
except:
    print("Invalid signature!")

# RESULT :

# Private key (32 bytes): b'a2bb9a42a1b1e416882a17978d6f28f21bc6433b7ff2e018e93fc7675b5b5449'
# Public key (32 bytes):  b'8726d8e8b730baa2c37689ecf2f041ab7382ad1af6ef17e341f05ba23af88db3'
# Signature (64 bytes): b'deccca050cf5dba61089e09da5ea9827f614c0b31c9230d75ba0c035f6576ea91c880aa4d64244453fcbd0099b1e064fb82eaf89c79c9a7dba74d674b2bd720e'
# The signature is valid.