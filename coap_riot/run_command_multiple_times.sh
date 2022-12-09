#!/bin/bash

for i in {1..10}; do coap-client -m get coap://[fe80::c40:45ff:fef1:a88b%tap0]/riot/did; done

for i in {1..10}; do coap-client -m put coap://[fe80::c40:45ff:fef1:a88b%tap0]/riot/did; done