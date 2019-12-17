/*
 * Copyright (c) 2019 Tobias Svehagen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_WIFI_ESP8266_H_
#define ZEPHYR_INCLUDE_DRIVERS_WIFI_ESP8266_H_

#include <kernel.h>
#include <net/net_context.h>
#include <net/net_if.h>
#include <net/net_ip.h>
#include <net/net_pkt.h>
#include <net/wifi_mgmt.h>

#include "modem_context.h"
#include "modem_cmd_handler.h"
#include "modem_iface_uart.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ESP8266_MAX_SOCKETS 5
#define ESP8266_PKT_BUF_LEN 256

/* Maximum amount that can be sent with CIPSEND and read with CIPRECVDATA */
#define ESP8266_MTU		2048
#define CIPRECVDATA_MAX_LEN	ESP8266_MTU

#define INVALID_LINK_ID		255

#define MDM_RING_BUF_SIZE	1024
#define MDM_RECV_MAX_BUF	30
#define MDM_RECV_BUF_SIZE	128
#define CMD_BUF_ALLOC_TIMEOUT	K_SECONDS(1)

#define ESP_CMD_TIMEOUT		K_SECONDS(10)
#define ESP_SCAN_TIMEOUT	K_SECONDS(10)
#define ESP_INIT_TIMEOUT	K_SECONDS(10)

extern struct esp8266_data esp8266_driver_data;

enum esp8266_socket_flags {
	ESP_SOCK_VALID      = BIT(1),
	ESP_SOCK_CONNECTING = BIT(2),
	ESP_SOCK_CONNECTED  = BIT(3)
};

struct esp8266_socket {
	/* internal */
	u8_t idx;
	u8_t link_id;
	u8_t flags;

	/* socket info */
	sa_family_t family;
	enum net_sock_type type;
	enum net_ip_protocol ip_proto;
	struct sockaddr src;
	struct sockaddr dst;

	/* for +CIPRECVDATA */
	size_t bytes_avail;

	/* packets */
	struct k_fifo fifo_rx_pkt;
	struct net_pkt *tx_pkt;

	/* sem */
	struct k_sem sem_data_ready;

	/* work */
	struct k_work connect_work;
	struct k_work send_work;
	struct k_work recv_work;
	struct k_work recvdata_work;

	/* net context */
	struct net_context *context;
	net_context_connect_cb_t connect_cb;
	net_context_send_cb_t send_cb;
	net_context_recv_cb_t recv_cb;

	/* callback data */
	void *conn_user_data;
	void *send_user_data;
	void *recv_user_data;
};

enum esp8266_data_flag {
	EDF_STA_CONNECTING = BIT(1),
	EDF_STA_CONNECTED  = BIT(2)
};

/* driver data */
struct esp8266_data {
	struct net_if *net_iface;

	u8_t flags;

	/* used to linearize net_pkt's during tx/rx */
	u8_t pkt_buf[ESP8266_PKT_BUF_LEN];

	/* addresses  */
	struct in_addr ip;
	struct in_addr gw;
	struct in_addr nm;
	u8_t mac_addr[6];

	/* modem context */
	struct modem_context mctx;

	/* modem interface */
	struct modem_iface_uart_data iface_data;
	u8_t iface_isr_buf[MDM_RECV_BUF_SIZE];
	u8_t iface_rb_buf[MDM_RING_BUF_SIZE];

	/* modem cmds */
	struct modem_cmd_handler_data cmd_handler_data;
	u8_t cmd_read_buf[MDM_RECV_BUF_SIZE];
	u8_t cmd_match_buf[MDM_RECV_BUF_SIZE];

	/* socket data */
	struct esp8266_socket sockets[ESP8266_MAX_SOCKETS];
	struct esp8266_socket *rx_sock;

	/* work */
	struct k_work_q workq;
	struct k_work init_work;
	struct k_delayed_work ip_addr_work;
	struct k_work scan_work;

	scan_result_cb_t scan_cb;

	/* response semaphore */
	struct k_sem sem_tx_ready;
	struct k_sem sem_response;
	struct k_sem sem_if_up;
};

int esp8266_offload_init(struct net_if *iface);

struct esp8266_socket *esp8266_socket_get();
int esp8266_socket_put(struct esp8266_socket *sock);
struct esp8266_socket *esp8266_socket_from_link_id(struct esp8266_data *data,
						   u8_t link_id);
void esp8266_socket_init(struct esp8266_data *data);

static inline
struct esp8266_data *esp8266_socket_to_dev(struct esp8266_socket *sock)
{
	return CONTAINER_OF(sock - sock->idx, struct esp8266_data, sockets);
}

static inline bool esp8266_socket_valid(struct esp8266_socket *sock)
{
	return (sock->flags & ESP_SOCK_VALID) != 0;
}

static inline bool esp8266_socket_connected(struct esp8266_socket *sock)
{
	return (sock->flags & ESP_SOCK_CONNECTED) != 0;
}

static inline void esp8266_flag_set(struct esp8266_data *dev,
				    enum esp8266_data_flag flag)
{
	dev->flags |= flag;
}

static inline void esp8266_flag_clear(struct esp8266_data *dev,
				      enum esp8266_data_flag flag)
{
	dev->flags &= (~flag);
}

static inline bool esp8266_flag_is_set(struct esp8266_data *dev,
				       enum esp8266_data_flag flag)
{
	return (dev->flags & flag) != 0;
}

/* FIXME:
 * Need to think a bit about where locking is needed
 */
static inline void esp8266_lock(struct esp8266_data *dev)
{
	/* k_mutex_lock(&dev->mtx_dev); */
}

static inline void esp8266_unlock(struct esp8266_data *dev)
{
	/* k_mutex_lock(&dev->mtx_dev); */
}

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_DRIVERS_WIFI_ESP8266_H_ */
