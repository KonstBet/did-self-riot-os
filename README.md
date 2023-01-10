# Method did:self for the RIOT OS
## Introduction
Decentralized Identifiers for the Internet of Things.
Implementation of the method did:self on RIOT OS.
Includes gateway proxy on python.
Use of CoAP Protocol for IoT.
## About
Implementation of method did:self on RIOT OS. Written in C programming language.
Includes a Gateway (CoAP proxy) written in Python.
Use for IoT Devices.

## Research
Based on [did:self](https://github.com/excid-io/did-self), which was written in Python.

## Usage
### Prerequisites
*	Include RIOT OS Folder from [RIOT](https://github.com/RIOT-OS/RIOT)
*	Install Python, C and any needed libraries

### Compile and Run (for Development)
Run CoAP Server on RIOT OS.
```
$ ./run_coap_server.sh
```
Run Gateway.
```
$ python3 gateway_coap_server_client.py
```
Read ipv6 address from running RIOT CoAP Server e.g.({"IPv6 addresses": ["fe80::381e:40ff:febf:26bf"]})
Add this new Device to the Gateway.
```
$ coap-client -m post coap://localhost/newdevice -e '{"ipv6": "fe80::381e:40ff:febf:26bf", "interface": "tap0"}'
```
Read Resources through the Gateway.
```
$ coap-client -m get coap://localhost/riot/board //READ BOARD
$ coap-client -m get coap://localhost/riot/did //READ DID Document & Proof
$ coap-client -m get coap://localhost/riot/data //READ DATA (the data are verified in gateway)
```

## Author
Konstantinos Betchavas