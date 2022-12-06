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


    // ipv6_addr_t* addr = malloc(sizeof(ipv6_addr_t));
    // netifs_get_ipv6(addr, 1);
    // char addr_str[IPV6_ADDR_MAX_STR_LEN];

    // ipv6_addr_to_str(addr_str, addr,IPV6_ADDR_MAX_STR_LEN);
    // printf("\n\n%s\n\n", addr_str);

    // ipv6_addr_to_str(addr_str, &ipv6_addr_all_nodes_link_local,IPV6_ADDR_MAX_STR_LEN);
    // printf("\n\n%s\n\n", addr_str);

    // ipv6_addr_from_str(addr, addr_str);

    // sock_udp_ep_t remote = { .port=COAP_PORT, .family=AF_INET6 };
    // remote.netif = SOCK_ADDR_ANY_NETIF;
    // memcpy(remote.addr.ipv6, addr->u8, 16);
    // nanocoap_sock_t *sock = malloc(sizeof(nanocoap_sock_t));
    // printf("\n\n%d\n\n",nanocoap_sock_connect(sock, &local, &remote));

    // coap_pkt_t *pkt = malloc(sizeof(coap_pkt_t));
    // pkt->hdr = malloc(sizeof(coap_hdr_t));
    // pkt->payload = malloc(sizeof(uint8_t));
    // pkt->token = malloc(sizeof(uint8_t));
    // nanocoap_sock_request(sock, pkt, COAP_INBUF_SIZE);


    nanocoap_server(&local, buf, sizeof(buf));

    /* should be never reached */
    return 0;
}
