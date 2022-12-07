#!/bin/bash

for i in {1..10}; do coap-client -m get coap://[fe80::50f3:22ff:fe6a:d2bb%tap0]/riot/did; done

for i in {1..10}; do coap-client -m put coap://[fe80::50f3:22ff:fe6a:d2bb%tap0]/riot/did; done