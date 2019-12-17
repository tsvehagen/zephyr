/*
 * Copyright (c) 2019 Tobias Svehagen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>

#include "esp8266.h"

/*
 * NOTE: It is assumed that the esp8266_data->mtx is held
 */

struct esp8266_socket *esp8266_socket_get(struct esp8266_data *data)
{
	struct esp8266_socket *sock;
	int i;

	for (i = 0; i < ARRAY_SIZE(data->sockets); ++i) {
		sock = &data->sockets[i];
		if (!esp8266_socket_valid(sock)) {
			break;
		}
	}

	if (esp8266_socket_valid(sock)) {
		return NULL;
	}

	sock->link_id = i;
	sock->flags |= ESP_SOCK_VALID;

	return sock;
}

int esp8266_socket_put(struct esp8266_socket *sock)
{
	sock->flags = 0;
	sock->link_id = INVALID_LINK_ID;
	return 0;
}

struct esp8266_socket *esp8266_socket_from_link_id(struct esp8266_data *data,
						   u8_t link_id)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(data->sockets); ++i) {
		if (esp8266_socket_valid(&data->sockets[i]) &&
		    data->sockets[i].link_id == link_id) {
			return &data->sockets[i];
		}
	}

	return NULL;
}

void esp8266_socket_init(struct esp8266_data *data)
{
	struct esp8266_socket *sock;
	int i;

	for (i = 0; i < ARRAY_SIZE(data->sockets); ++i) {
		sock = &data->sockets[i];
		sock->idx = i;
		sock->link_id = INVALID_LINK_ID;
		k_sem_init(&sock->sem_data_ready, 0, 1);
		k_fifo_init(&sock->fifo_rx_pkt);
	}
}
