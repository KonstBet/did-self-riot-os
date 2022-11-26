/*
 * Copyright (C) 2016 Kaspar Schleiser <kaspar@schleiser.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       CoAP example server application (using nanocoap)
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @}
 */

#include <stdio.h>

#include "net/nanocoap_sock.h"
#include "xtimer.h"

#define COAP_INBUF_SIZE (256U)

#define MAIN_QUEUE_SIZE     (8)
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

int main(void)
{
    puts("RIOT nanocoap example application");

    /* nanocoap_server uses gnrc sock which uses gnrc which needs a msg queue */
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);

    puts("Waiting for address autoconfiguration...");
    xtimer_sleep(2);

    /* print network addresses */
    printf("{\"IPv6 addresses\": [\"");
    netifs_print_ipv6("\", \"");
    puts("\"]}");

    /* initialize nanocoap server instance */
    uint8_t buf[COAP_INBUF_SIZE];
    sock_udp_ep_t local = { .port=COAP_PORT, .family=AF_INET6 };


    // uint8_t buf2[COAP_INBUF_SIZE];
    // coap_opt_put_uri_path(buf2, 0, "newdevice");
    // coap_pkt_t pkt;
    // memcpy(pkt.payload, "Hello World!", 12);
    // pkt.payload_len = 12;

    // sock_udp_ep_t remote = { .family=AF_INET, .netif=SOCK_ADDR_ANY_NETIF };
    // remote.addr.ipv4[0] = 224;
    // remote.addr.ipv4[1] = 0;
    // remote.addr.ipv4[2] = 1;
    // remote.addr.ipv4[3] = 187;
    // remote.port = 5683;
    // ssize_t size_t = nanocoap_request(&pkt, &local, &remote, 0);
    // printf("%d", size_t);

    nanocoap_server(&local, buf, sizeof(buf));

    /* should be never reached */
    return 0;
}
