/*
 * Copyright (c) 2019 Tobias Svehagen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_LEVEL CONFIG_WIFI_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(wifi_esp8266_offload);

#include <zephyr.h>
#include <kernel.h>
#include <device.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/net_offload.h>

#include "esp8266.h"

static int esp8266_bind(struct net_context *context,
			const struct sockaddr *addr,
			socklen_t addrlen)
{
	struct esp8266_socket *sock;

	sock = (struct esp8266_socket *)context->offload_context;

	sock->src.sa_family = addr->sa_family;

	if (IS_ENABLED(CONFIG_NET_IPV4) && addr->sa_family == AF_INET) {
		net_ipaddr_copy(&net_sin(&sock->src)->sin_addr,
				&net_sin(addr)->sin_addr);
		net_sin(&sock->src)->sin_port = net_sin(addr)->sin_port;
	} else {
		return -EAFNOSUPPORT;
	}

	return 0;
}

static int esp8266_listen(struct net_context *context, int backlog)
{
	return -ENOTSUP;
}

static int _sock_connect(struct esp8266_data *dev, struct esp8266_socket *sock)
{
	char addr_str[NET_IPV4_ADDR_LEN];
	char connect_msg[100];
	int ret;

	if (!esp8266_flag_is_set(dev, EDF_STA_CONNECTED)) {
		return -ENETUNREACH;
	}

	if (sock->ip_proto == IPPROTO_TCP) {
		net_addr_ntop(sock->dst.sa_family,
			      &net_sin(&sock->dst)->sin_addr,
			      addr_str, sizeof(addr_str));
		snprintk(connect_msg, sizeof(connect_msg),
			 "AT+CIPSTART=%d,\"TCP\",\"%s\",%d,7200",
			 sock->link_id, addr_str,
			 ntohs(net_sin(&sock->dst)->sin_port));
	} else {
		net_addr_ntop(sock->dst.sa_family,
			      &net_sin(&sock->dst)->sin_addr,
			      addr_str, sizeof(addr_str));
		snprintk(connect_msg, sizeof(connect_msg),
			 "AT+CIPSTART=%d,\"UDP\",\"%s\",%d",
			 sock->link_id, addr_str,
			 ntohs(net_sin(&sock->dst)->sin_port));
	}

	LOG_DBG("link %d, ip_proto %s, addr %s", sock->link_id,
		sock->ip_proto == IPPROTO_TCP ? "TCP" : "UDP",
		log_strdup(addr_str));

	ret = modem_cmd_send(&dev->mctx.iface, &dev->mctx.cmd_handler,
			     NULL, 0, connect_msg, &dev->sem_response,
			     ESP_CMD_TIMEOUT);
	if (ret == 0) {
		sock->flags |= ESP_SOCK_CONNECTED;
	} else if (ret == -ETIMEDOUT) {
		/* FIXME:
		 * What if the connection finishes after we return from
		 * here? The caller might think that it can discard the
		 * socket. Set some flag to indicate that the link should
		 * be closed if it ever connects?
		 */
	}

	return ret;
}

static void esp8266_connect_work(struct k_work *work)
{
	net_context_connect_cb_t cb;
	struct net_context *context;
	struct esp8266_socket *sock;
	struct esp8266_data *dev;
	void *user_data;
	int ret;

	sock = CONTAINER_OF(work, struct esp8266_socket, connect_work);
	dev = esp8266_socket_to_dev(sock);

	esp8266_lock(dev);

	cb = sock->connect_cb;
	context = sock->context;
	user_data = sock->conn_user_data;

	ret = _sock_connect(dev, sock);

	esp8266_unlock(dev);

	if (cb) {
		cb(context, ret, user_data);
	}

}

static int esp8266_connect(struct net_context *context,
			   const struct sockaddr *addr,
			   socklen_t addrlen,
			   net_context_connect_cb_t cb,
			   s32_t timeout,
			   void *user_data)
{
	struct esp8266_socket *sock;
	struct esp8266_data *dev;
	int ret;

	sock = (struct esp8266_socket *)context->offload_context;
	dev = esp8266_socket_to_dev(sock);

	LOG_DBG("link %d, timeout %d", sock->link_id, timeout);

	if (!IS_ENABLED(CONFIG_NET_IPV4) || addr->sa_family != AF_INET) {
		return -EAFNOSUPPORT;
	}

	esp8266_lock(dev);

	if (esp8266_socket_connected(sock)) {
		esp8266_unlock(dev);
		return -EISCONN;
	}

	sock->dst = *addr;
	sock->connect_cb = cb;
	sock->conn_user_data = user_data;

	if (timeout == K_NO_WAIT) {
		k_work_submit_to_queue(&dev->workq, &sock->connect_work);
		esp8266_unlock(dev);
		return 0;
	}

	ret = _sock_connect(dev, sock);

	if (esp8266_socket_connected(sock) && sock->tx_pkt) {
		k_work_submit_to_queue(&dev->workq, &sock->send_work);
	}

	esp8266_unlock(dev);

	if (ret != -ETIMEDOUT && cb) {
		cb(context, ret, user_data);
	}

	return ret;
}

static int esp8266_accept(struct net_context *context,
			     net_tcp_accept_cb_t cb, s32_t timeout,
			     void *user_data)
{
	return -ENOTSUP;
}

MODEM_CMD_DIRECT_DEFINE(on_cmd_tx_ready)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);

	k_sem_give(&dev->sem_tx_ready);
	data->ret = len;
}

MODEM_CMD_DEFINE(on_cmd_send_ok)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);

	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&dev->sem_response);
}

MODEM_CMD_DEFINE(on_cmd_send_fail)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);

	modem_cmd_handler_set_error(data, -EIO);
	k_sem_give(&dev->sem_response);
}

static int _sock_send(struct esp8266_data *dev, struct esp8266_socket *sock)
{
	char cmd_buf[64], addr_str[NET_IPV4_ADDR_LEN];
	int ret, write_len, pkt_len;
	struct modem_cmd cmds[] = {
		MODEM_CMD_DIRECT(">", on_cmd_tx_ready),
		MODEM_CMD("SEND OK", on_cmd_send_ok, 0U, ""),
		MODEM_CMD("SEND FAIL", on_cmd_send_fail, 0U, ""),
	};

	if (!esp8266_flag_is_set(dev, EDF_STA_CONNECTED)) {
		return -ENETUNREACH;
	}

	pkt_len = net_pkt_get_len(sock->tx_pkt);

	LOG_DBG("link %d, len %d", sock->link_id, pkt_len);

	if (sock->ip_proto == IPPROTO_TCP) {
		snprintk(cmd_buf, sizeof(cmd_buf),
			 "AT+CIPSEND=%d,%d", sock->link_id, pkt_len);
	} else {
		net_addr_ntop(sock->dst.sa_family,
			      &net_sin(&sock->dst)->sin_addr,
			      addr_str, sizeof(addr_str));
		snprintk(cmd_buf, sizeof(cmd_buf),
			 "AT+CIPSEND=%d,%d,\"%s\",%d",
			 sock->link_id, pkt_len, addr_str,
			 ntohs(net_sin(&sock->dst)->sin_port));
	}

	k_sem_take(&dev->cmd_handler_data.sem_tx_lock, K_FOREVER);
	k_sem_reset(&dev->sem_tx_ready);

	ret = modem_cmd_send_nolock(&dev->mctx.iface, &dev->mctx.cmd_handler,
			     NULL, 0, cmd_buf, &dev->sem_response,
			     ESP_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_DBG("Failed to send command");
		goto out;
	}

	ret = modem_cmd_handler_update_cmds(&dev->cmd_handler_data,
					    cmds, ARRAY_SIZE(cmds),
					    true);
	if (ret < 0) {
		goto out;
	}

	/*
	 * After modem handlers have been updated the receive buffer
	 * needs to be processed again since there might now be a match.
	 */
	k_sem_give(&dev->iface_data.rx_sem);

	/* Wait for '>' */
	ret = k_sem_take(&dev->sem_tx_ready, 5000);
	if (ret < 0) {
		LOG_DBG("Timeout waiting for tx");
		goto out;
	}

	while (pkt_len) {
		write_len = MIN(pkt_len, sizeof(dev->pkt_buf));
		net_pkt_read(sock->tx_pkt, dev->pkt_buf, write_len);
		dev->mctx.iface.write(&dev->mctx.iface, dev->pkt_buf,
				      write_len);
		pkt_len -= write_len;
	}

	/* Wait for 'SEND OK' or 'SEND FAIL' */
	k_sem_reset(&dev->sem_response);
	ret = k_sem_take(&dev->sem_response, ESP_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_DBG("No send response");
		goto out;
	}

	ret = modem_cmd_handler_get_error(&dev->cmd_handler_data);
	if (ret != 0) {
		LOG_DBG("Failed to send data");
	}

out:
	(void)modem_cmd_handler_update_cmds(&dev->cmd_handler_data,
					    NULL, 0U, false);
	k_sem_give(&dev->cmd_handler_data.sem_tx_lock);

	net_pkt_unref(sock->tx_pkt);
	sock->tx_pkt = NULL;

	return ret;
}

static void esp8266_send_work(struct k_work *work)
{
	struct esp8266_socket *sock;
	struct net_context *context;
	net_context_send_cb_t cb;
	struct esp8266_data *dev;
	void *user_data;
	int ret = 0;

	sock = CONTAINER_OF(work, struct esp8266_socket, send_work);
	dev = esp8266_socket_to_dev(sock);

	esp8266_lock(dev);

	cb = sock->send_cb;
	context = sock->context;
	user_data = sock->send_user_data;

	ret = _sock_send(dev, sock);
	if (ret < 0) {
		LOG_ERR("Failed to send data: link %d, ret %d", sock->link_id,
			ret);
	}

	esp8266_unlock(dev);

	if (cb) {
		cb(context, ret, user_data);
	}
}

static int esp8266_sendto(struct net_pkt *pkt,
			  const struct sockaddr *dst_addr,
			  socklen_t addrlen,
			  net_context_send_cb_t cb,
			  s32_t timeout,
			  void *user_data)
{
	struct net_context *context;
	struct esp8266_socket *sock;
	struct esp8266_data *dev;
	int ret = 0;

	context = pkt->context;
	sock = (struct esp8266_socket *)context->offload_context;
	dev = esp8266_socket_to_dev(sock);

	LOG_DBG("link %d, timeout %d", sock->link_id, timeout);

	esp8266_lock(dev);

	if (sock->tx_pkt) {
		esp8266_unlock(dev);
		return -EBUSY;
	}

	if (sock->type == SOCK_STREAM) {
		if (!esp8266_socket_connected(sock)) {
			esp8266_unlock(dev);
			return -ENOTCONN;
		} else if (dst_addr) {
			esp8266_unlock(dev);
			return -EISCONN;
		}
	} else {
		if (!esp8266_socket_connected(sock)) {
			if (!dst_addr) {
				esp8266_unlock(dev);
				return -ENOTCONN;
			}

			/* Use a timeout of 5000 ms here even though the
			 * timeout parameter might be different. We want to
			 * have a valid link id before proceeding.
			 */
			ret = esp8266_connect(context, dst_addr, addrlen, NULL,
					      K_SECONDS(5), NULL);
			if (ret < 0) {
				esp8266_unlock(dev);
				return ret;
			}
		} else if (dst_addr && memcmp(dst_addr, &sock->dst, addrlen)) {
			/* This might be unexpected behaviour but the ESP8266
			 * doesn't support changing endpoint.
			 */
			esp8266_unlock(dev);
			return -EISCONN;
		}
	}

	sock->tx_pkt = pkt;
	sock->send_cb = cb;
	sock->send_user_data = user_data;

	if (timeout == K_NO_WAIT) {
		k_work_submit_to_queue(&dev->workq, &sock->send_work);
		esp8266_unlock(dev);
		return 0;
	}

	ret = _sock_send(dev, sock);
	if (ret < 0) {
		LOG_ERR("Failed to send data: link %d, ret %d", sock->link_id,
			ret);
	}

	esp8266_unlock(dev);

	if (cb) {
		cb(context, ret, user_data);
	}

	return ret;
}

static int esp8266_send(struct net_pkt *pkt,
			net_context_send_cb_t cb,
			s32_t timeout,
			void *user_data)
{
	return esp8266_sendto(pkt, NULL, 0, cb, timeout, user_data);
}

#define CIPRECVDATA_CMD_MIN_LEN (sizeof("+CIPRECVDATA,L:") - 1)
#define CIPRECVDATA_CMD_MAX_LEN (sizeof("+CIPRECVDATA,LLLL:") - 1)
MODEM_CMD_DIRECT_DEFINE(on_cmd_ciprecvdata)
{
	char *endptr, cmd_buf[CIPRECVDATA_CMD_MAX_LEN + 1];
	int data_offset, data_len, read_len;
	size_t match_len, frags_len;
	struct esp8266_socket *sock;
	struct esp8266_data *dev;
	struct net_pkt *pkt;

	dev = CONTAINER_OF(data, struct esp8266_data, cmd_handler_data);

	esp8266_lock(dev);

	sock = dev->rx_sock;

	frags_len = net_buf_frags_len(data->rx_buf);
	if (frags_len < CIPRECVDATA_CMD_MIN_LEN) {
		data->ret = -EAGAIN;
		goto out;
	}

	match_len = net_buf_linearize(cmd_buf, CIPRECVDATA_CMD_MAX_LEN,
				      data->rx_buf, 0, CIPRECVDATA_CMD_MAX_LEN);

	cmd_buf[match_len] = 0;

	data_len = strtol(&cmd_buf[len], &endptr, 10);
	if (endptr == &cmd_buf[len] ||
	    (*endptr == 0 && match_len >= CIPRECVDATA_CMD_MAX_LEN) ||
	    data_len > sock->bytes_avail) {
		LOG_ERR("Invalid cmd: %s", log_strdup(cmd_buf));
		data->ret = len;
		goto out;
	} else if (*endptr == 0) {
		data->ret = -EAGAIN;
		goto out;
	} else if (*endptr != ':') {
		LOG_ERR("Invalid end of cmd: 0x%02x != 0x%02x", *endptr, ':');
		data->ret = len;
		goto out;
	}

	*endptr = 0;

	/* data_offset is the offset to where the actual data starts */
	data_offset = strlen(cmd_buf) + 1;

	/* FIXME: Inefficient way of waiting for data */
	if (data_offset + data_len > frags_len) {
		data->ret = -EAGAIN;
		goto out;
	}

	sock->bytes_avail -= data_len;
	data->ret = data_offset + data_len;

	pkt = net_pkt_rx_alloc_with_buffer(dev->net_iface, data_len, AF_UNSPEC,
					   0, K_NO_WAIT);
	if (!pkt) {
		LOG_ERR("Failed to allocate buffer: len %d", data_len);
		goto out;
	}

	while (data_len) {
		read_len = MIN(data_len, sizeof(dev->pkt_buf));
		net_buf_linearize(dev->pkt_buf, read_len, data->rx_buf,
				  data_offset, read_len);
		net_pkt_write(pkt, dev->pkt_buf, read_len);
		data_offset += read_len;
		data_len -= read_len;
	}

	net_pkt_cursor_init(pkt);
	k_fifo_put(&sock->fifo_rx_pkt, pkt);
	k_work_submit_to_queue(&dev->workq, &sock->recv_work);

out:
	esp8266_unlock(dev);
}

static void esp8266_recvdata_work(struct k_work *work)
{
	struct esp8266_socket *sock;
	struct esp8266_data *dev;
	int len = CIPRECVDATA_MAX_LEN, ret;
	char cmd[32];
	struct modem_cmd cmds[] = {
		MODEM_CMD_DIRECT("+CIPRECVDATA,", on_cmd_ciprecvdata),
	};

	sock = CONTAINER_OF(work, struct esp8266_socket, recvdata_work);
	dev = esp8266_socket_to_dev(sock);

	esp8266_lock(dev);

	LOG_DBG("%d bytes available on link %d", sock->bytes_avail,
		sock->link_id);

	if (sock->bytes_avail == 0) {
		LOG_WRN("No data available on link %d", sock->link_id);
		return;
	} else if (len > sock->bytes_avail) {
		len = sock->bytes_avail;
	}

	dev->rx_sock = sock;

	snprintk(cmd, sizeof(cmd), "AT+CIPRECVDATA=%d,%d", sock->link_id, len);

	ret = modem_cmd_send(&dev->mctx.iface, &dev->mctx.cmd_handler,
			     cmds, ARRAY_SIZE(cmds), cmd, &dev->sem_response,
			     ESP_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Timeout during rx: link %d, ret %d", sock->link_id,
			ret);
	} else if (sock->bytes_avail > 0) {
		k_work_submit_to_queue(&dev->workq, &sock->recvdata_work);
	}

	esp8266_unlock(dev);
}


static void esp8266_recv_work(struct k_work *work)
{
	struct esp8266_socket *sock;
	struct esp8266_data *dev;
	struct net_pkt *pkt;

	sock = CONTAINER_OF(work, struct esp8266_socket, recv_work);
	dev = esp8266_socket_to_dev(sock);

	esp8266_lock(dev);

	pkt = k_fifo_get(&sock->fifo_rx_pkt, K_NO_WAIT);
	while (pkt) {
		if (sock->recv_cb) {
			sock->recv_cb(sock->context, pkt, NULL, NULL,
				      0, sock->recv_user_data);
			k_sem_give(&sock->sem_data_ready);
		} else {
			/* Discard */
			net_pkt_unref(pkt);
		}

		pkt = k_fifo_get(&sock->fifo_rx_pkt, K_NO_WAIT);
	}

	/* Should we notify that the socket has been closed? */
	if (!esp8266_socket_connected(sock) && sock->bytes_avail == 0 &&
	    sock->recv_cb) {
		sock->recv_cb(sock->context, NULL, NULL, NULL, 0,
			      sock->recv_user_data);
		k_sem_give(&sock->sem_data_ready);
	}
}

static int esp8266_recv(struct net_context *context,
			net_context_recv_cb_t cb,
			s32_t timeout,
			void *user_data)
{
	struct esp8266_socket *sock;
	struct esp8266_data *dev;
	int ret;

	sock = (struct esp8266_socket *)context->offload_context;
	dev = esp8266_socket_to_dev(sock);

	LOG_DBG("link_id %d, timeout %d, cb 0x%x, data 0x%x", sock->link_id,
		timeout, (int)cb, (int)user_data);

	sock->recv_cb = cb;
	sock->recv_user_data = user_data;
	k_sem_reset(&sock->sem_data_ready);

	if (timeout == K_NO_WAIT) {
		return 0;
	}

	ret = k_sem_take(&sock->sem_data_ready, timeout);

	esp8266_lock(dev);
	sock->recv_cb = NULL;
	esp8266_unlock(dev);

	return ret;
}

static int esp8266_put(struct net_context *context)
{
	struct esp8266_socket *sock;
	struct esp8266_data *data;
	struct net_pkt *pkt;
	char cmd_buf[16];
	int ret;

	sock = (struct esp8266_socket *)context->offload_context;
	data = esp8266_socket_to_dev(sock);

	esp8266_lock(data);

	if (esp8266_socket_connected(sock)) {
		snprintk(cmd_buf, sizeof(cmd_buf), "AT+CIPCLOSE=%d",
			 sock->link_id);
		ret = modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
				     NULL, 0, cmd_buf, &data->sem_response,
				     ESP_CMD_TIMEOUT);
		if (ret < 0) {
			LOG_ERR("Failed to close link %d, ret %d",
				sock->link_id, ret);
		}
	}

	sock->connect_cb = NULL;
	sock->recv_cb = NULL;
	sock->send_cb = NULL;
	sock->tx_pkt = NULL;

	/* Drain rxfifo */
	for (pkt = k_fifo_get(&sock->fifo_rx_pkt, K_NO_WAIT);
	     pkt != NULL;
	     pkt = k_fifo_get(&sock->fifo_rx_pkt, K_NO_WAIT)) {
		net_pkt_unref(pkt);
	}

	esp8266_socket_put(sock);

	esp8266_unlock(data);

	return 0;
}

static int esp8266_get(sa_family_t family,
		       enum net_sock_type type,
		       enum net_ip_protocol ip_proto,
		       struct net_context **context)
{
	struct esp8266_socket *sock;
	struct esp8266_data *dev;

	LOG_DBG("");

	if (family != AF_INET) {
		return -EAFNOSUPPORT;
	}

	/* FIXME:
	 * iface has not yet been assigned to context so there is currently
	 * no way to know which interface to operate on. Therefore this driver
	 * only supports one device node.
	 */
	dev = &esp8266_driver_data;

	esp8266_lock(dev);

	sock = esp8266_socket_get(&esp8266_driver_data);
	if (sock == NULL) {
		return -ENOMEM;
	}

	k_work_init(&sock->connect_work, esp8266_connect_work);
	k_work_init(&sock->send_work, esp8266_send_work);
	k_work_init(&sock->recv_work, esp8266_recv_work);
	k_work_init(&sock->recvdata_work, esp8266_recvdata_work);
	sock->family = family;
	sock->type = type;
	sock->ip_proto = ip_proto;
	sock->context = *context;
	(*context)->offload_context = sock;

	esp8266_unlock(dev);

	return 0;
}

static struct net_offload esp8266_offload = {
	.get	       = esp8266_get,
	.bind	       = esp8266_bind,
	.listen	       = esp8266_listen,
	.connect       = esp8266_connect,
	.accept	       = esp8266_accept,
	.send	       = esp8266_send,
	.sendto	       = esp8266_sendto,
	.recv	       = esp8266_recv,
	.put	       = esp8266_put,
};

int esp8266_offload_init(struct net_if *iface)
{
	iface->if_dev->offload = &esp8266_offload;

	return 0;
}
