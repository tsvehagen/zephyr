/*
 * Copyright (c) 2019 Tobias Svehagen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define LOG_LEVEL CONFIG_WIFI_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(wifi_esp8266);

#include <kernel.h>
#include <ctype.h>
#include <errno.h>
#include <zephyr.h>
#include <device.h>
#include <init.h>
#include <stdlib.h>

#include <drivers/gpio.h>

#include <net/net_if.h>
#include <net/net_offload.h>
#include <net/wifi_mgmt.h>

#include "esp8266.h"

/* pin settings */
enum modem_control_pins {
#if defined(DT_INST_0_ESPRESSIF_ESP8266_WIFI_RESET_GPIOS_PIN)
	WIFI_RESET,
#endif
	NUM_PINS,
};

static struct modem_pin modem_pins[] = {
#if defined(DT_INST_0_ESPRESSIF_ESP8266_WIFI_RESET_GPIOS_PIN)
	MODEM_PIN(DT_INST_0_ESPRESSIF_ESP8266_WIFI_RESET_GPIOS_CONTROLLER,
		  DT_INST_0_ESPRESSIF_ESP8266_WIFI_RESET_GPIOS_PIN,
		  GPIO_DIR_OUT),
#endif
};

#define WIFI_UART_DEV_NAME		DT_INST_0_ESPRESSIF_ESP8266_BUS_NAME


NET_BUF_POOL_DEFINE(mdm_recv_pool, MDM_RECV_MAX_BUF, MDM_RECV_BUF_SIZE,
		    0, NULL);

/* RX thread structures */
K_THREAD_STACK_DEFINE(esp_rx_stack,
		      CONFIG_WIFI_ESP8266_RX_STACK_SIZE);
struct k_thread esp_rx_thread;

/* RX thread work queue */
K_THREAD_STACK_DEFINE(esp_workq_stack,
		      CONFIG_WIFI_ESP8266_WORKQ_STACK_SIZE);

struct esp8266_data esp8266_driver_data;

/*
 * Modem Response Command Handlers
 */

/* Handler: OK */
MODEM_CMD_DEFINE(on_cmd_ok)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);

	modem_cmd_handler_set_error(data, 0);
	k_sem_give(&dev->sem_response);
}

/* Handler: ERROR */
MODEM_CMD_DEFINE(on_cmd_error)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);

	modem_cmd_handler_set_error(data, -EIO);
	k_sem_give(&dev->sem_response);
}

/* RX thread */
static void esp8266_rx(struct device *dev)
{
	struct esp8266_data *data = dev->driver_data;

	while (true) {
		/* wait for incoming data */
		k_sem_take(&data->iface_data.rx_sem, K_FOREVER);

		data->mctx.cmd_handler.process(&data->mctx.cmd_handler,
					       &data->mctx.iface);

		/* give up time if we have a solid stream of data */
		k_yield();
	}
}

static char *str_unquote(char *str)
{
	char *end;

	if (str[0] != '"') {
		return str;
	}

	str++;

	end = strrchr(str, '"');
	if (end != NULL) {
		*end = 0;
	}

	return str;
}

/* +CIPSTAMAC_CUR:"xx:xx:xx:xx:xx:xx" */
MODEM_CMD_DEFINE(on_cmd_cipstamac)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);
	char *mac;

	mac = str_unquote(argv[0]);
	net_bytes_from_str(dev->mac_addr, sizeof(dev->mac_addr), mac);
}

MODEM_CMD_DEFINE(on_cmd_cwlap)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);
	struct wifi_scan_result res = { 0 };
	int i;

	i = strtol(argv[0], NULL, 10);
	if (i == 0) {
		res.security = WIFI_SECURITY_TYPE_NONE;
	} else {
		res.security = WIFI_SECURITY_TYPE_PSK;
	}

	argv[1] = str_unquote(argv[1]);
	i = strlen(argv[1]);
	if (i > sizeof(res.ssid)) {
		i = sizeof(res.ssid);
	}

	memcpy(res.ssid, argv[1], i);
	res.ssid_length = i;
	res.rssi = strtol(argv[2], NULL, 10);
	res.channel = strtol(argv[3], NULL, 10);

	if (dev->scan_cb) {
		dev->scan_cb(dev->net_iface, 0, &res);
	}
}

static struct modem_cmd response_cmds[] = {
	MODEM_CMD("OK", on_cmd_ok, 0U, ""), /* 3GPP */
	MODEM_CMD("ERROR", on_cmd_error, 0U, ""), /* 3GPP */
};

MODEM_CMD_DEFINE(on_cmd_wifi_connected)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);

	esp8266_flag_set(dev, EDF_STA_CONNECTED);
	esp8266_flag_clear(dev, EDF_STA_CONNECTING);
	wifi_mgmt_raise_connect_result_event(dev->net_iface, 0);
}

MODEM_CMD_DEFINE(on_cmd_wifi_disconnected)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);

	esp8266_flag_clear(dev, EDF_STA_CONNECTED);
	esp8266_flag_clear(dev, EDF_STA_CONNECTING);
	net_if_ipv4_addr_rm(dev->net_iface, &dev->ip);
	wifi_mgmt_raise_disconnect_result_event(dev->net_iface, 0);
}

/*
 * +CIPSTA_CUR:ip:"<ip>"
 * +CIPSTA_CUR:gateway:"<ip>"
 * +CIPSTA_CUR:netmask:"<ip>"
 */
MODEM_CMD_DEFINE(on_cmd_cipsta)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);
	char *ip;

	ip = str_unquote(argv[1]);

	if (!strcmp(argv[0], "ip")) {
		net_addr_pton(AF_INET, ip, &dev->ip);
	} else if (!strcmp(argv[0], "gateway")) {
		net_addr_pton(AF_INET, ip, &dev->gw);
	} else if (!strcmp(argv[0], "netmask")) {
		net_addr_pton(AF_INET, ip, &dev->nm);
	} else {
		LOG_WRN("Unknown IP type %s", log_strdup(argv[0]));
	}
}

static void esp8266_ip_addr_work(struct k_work *work)
{
	struct esp8266_data *data = CONTAINER_OF(work, struct esp8266_data,
						 ip_addr_work);
	struct modem_cmd cmds[] = {
		MODEM_CMD("+CIPSTA_CUR:", on_cmd_cipsta, 2U, ":"),
	};

	modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
			cmds, ARRAY_SIZE(cmds), "AT+CIPSTA_CUR?",
			&data->sem_response, ESP_CMD_TIMEOUT);

	/* update interface addresses */
	net_if_ipv4_set_gw(data->net_iface, &data->gw);
	net_if_ipv4_set_netmask(data->net_iface, &data->nm);
	net_if_ipv4_addr_add(data->net_iface, &data->ip, NET_ADDR_DHCP, 0);
}

MODEM_CMD_DEFINE(on_cmd_got_ip)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);

	k_delayed_work_submit_to_queue(&dev->workq, &dev->ip_addr_work,
				       K_SECONDS(1));
}

MODEM_CMD_DEFINE(on_cmd_connect)
{
	struct esp8266_socket *sock;
	struct esp8266_data *dev;
	u8_t link_id;

	link_id = data->match_buf[0] - '0';

	dev = CONTAINER_OF(data, struct esp8266_data, cmd_handler_data);
	sock = esp8266_socket_from_link_id(dev, link_id);
	if (sock == NULL) {
		LOG_ERR("No socket for link %d", link_id);
		return;
	}
}

MODEM_CMD_DEFINE(on_cmd_closed)
{
	struct esp8266_socket *sock;
	struct esp8266_data *dev;
	u8_t link_id;

	link_id = data->match_buf[0] - '0';

	dev = CONTAINER_OF(data, struct esp8266_data, cmd_handler_data);
	sock = esp8266_socket_from_link_id(dev, link_id);
	if (sock == NULL) {
		LOG_ERR("No socket for link %d", link_id);
		return;
	}

	if (!esp8266_socket_connected(sock)) {
		LOG_WRN("Link %d already closed", link_id);
		return;
	}

	sock->flags &= ~(ESP_SOCK_CONNECTED);
	k_work_submit_to_queue(&dev->workq, &sock->recv_work);
}

/*
 * Passive TCP: "+IPD,<id>,<len>\r\n"
 * Other:       "+IPD,<id>,<len>:<data>"
 */
#define MIN_IPD_LEN (sizeof("+IPD,I,LE") - 1)
#define MAX_IPD_LEN (sizeof("+IPD,I,LLLLE") - 1)
MODEM_CMD_DIRECT_DEFINE(on_cmd_ipd)
{
	char *endptr, end, ipd_buf[MAX_IPD_LEN + 1];
	int data_offset, data_len, read_len;
	size_t match_len, frags_len;
	struct esp8266_socket *sock;
	struct esp8266_data *dev;
	struct net_pkt *pkt;
	u8_t link_id;

	dev = CONTAINER_OF(data, struct esp8266_data, cmd_handler_data);

	esp8266_lock(dev);

	frags_len = net_buf_frags_len(data->rx_buf);

	/* Wait until minimum cmd length is available */
	if (frags_len < MIN_IPD_LEN) {
		data->ret = -EAGAIN;
		goto out;
	}

	match_len = net_buf_linearize(ipd_buf, MAX_IPD_LEN,
				      data->rx_buf, 0, MAX_IPD_LEN);

	ipd_buf[match_len] = 0;
	if (ipd_buf[len] != ',' || ipd_buf[len + 2] != ',') {
		LOG_ERR("Invalid IPD: %s", log_strdup(ipd_buf));
		data->ret = len;
		goto out;
	}

	link_id = ipd_buf[len + 1] - '0';
	sock = esp8266_socket_from_link_id(dev, link_id);
	if (sock == NULL) {
		LOG_ERR("No socket for link %d", link_id);
		data->ret = len;
		goto out;
	}

	/* When using passive TCP, the +IPD command ends with \r\n */
	if (IS_ENABLED(CONFIG_WIFI_ESP8266_PASSIVE_TCP) &&
	    sock->ip_proto == IPPROTO_TCP) {
		end = '\r';
	} else {
		end = ':';
	}

	data_len = strtol(&ipd_buf[len + 3], &endptr, 10);
	if (endptr == &ipd_buf[len + 3] ||
	    (*endptr == 0 && match_len >= MAX_IPD_LEN)) {
		/* Invalid */
		LOG_ERR("Invalid IPD len: %s", log_strdup(ipd_buf));
		data->ret = len;
		goto out;
	} else if (*endptr == 0) {
		data->ret = -EAGAIN;
		goto out;
	} else if (*endptr != end) {
		LOG_ERR("Invalid cmd end 0x%02x, expected 0x%02x", *endptr,
			end);
		data->ret = len;
		goto out;
	}

	*endptr = 0;
	data_offset = strlen(ipd_buf) + 1;

	/*
	 * When using passive TCP, the data itself is not included in the +IPD
	 * command but must be polled with AT+CIPRECVDATA.
	 */
	if (IS_ENABLED(CONFIG_WIFI_ESP8266_PASSIVE_TCP) &&
	    sock->ip_proto == IPPROTO_TCP) {
		sock->bytes_avail = data_len;
		k_work_submit_to_queue(&dev->workq, &sock->recvdata_work);
		data->ret = data_offset;
		return;
	}

	/* Do we have the whole message? */
	if (data_offset + data_len > frags_len) {
		data->ret = -EAGAIN;
		return;
	}

	data->ret = data_offset + data_len; /* Skip */

	pkt = net_pkt_rx_alloc_with_buffer(dev->net_iface, data_len, AF_UNSPEC,
					   0, K_NO_WAIT);
	if (!pkt) {
		LOG_ERR("Could not allocate net_pkt");
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

MODEM_CMD_DEFINE(on_cmd_busy_sending)
{
	LOG_WRN("Busy sending");
}

MODEM_CMD_DEFINE(on_cmd_busy_processing)
{
	LOG_WRN("Busy processing");
}

/*
 * The 'ready' command is sent when device has booted and is ready to receive
 * commands. It is only expected after a reset of the device.
 */
MODEM_CMD_DEFINE(on_cmd_ready)
{
	struct esp8266_data *dev = CONTAINER_OF(data, struct esp8266_data,
						cmd_handler_data);

	if (net_if_is_up(dev->net_iface)) {
		net_if_down(dev->net_iface);
		LOG_ERR("Unexpected reset");
	}

	if (esp8266_flag_is_set(dev, EDF_STA_CONNECTING)) {
		esp8266_flag_clear(dev, EDF_STA_CONNECTING);
		wifi_mgmt_raise_connect_result_event(dev->net_iface, -1);
	} else if (esp8266_flag_is_set(dev, EDF_STA_CONNECTED)) {
		esp8266_flag_clear(dev, EDF_STA_CONNECTED);
		wifi_mgmt_raise_disconnect_result_event(dev->net_iface, 0);
	}

	net_if_ipv4_addr_rm(dev->net_iface, &dev->ip);
	k_work_submit_to_queue(&dev->workq, &dev->init_work);
}

static struct modem_cmd unsol_cmds[] = {
	MODEM_CMD("WIFI CONNECTED", on_cmd_wifi_connected, 0U, ""),
	MODEM_CMD("WIFI DISCONNECT", on_cmd_wifi_disconnected, 0U, ""),
	MODEM_CMD("WIFI GOT IP", on_cmd_got_ip, 0U, ""),
	MODEM_CMD("0,CONNECT", on_cmd_connect, 0U, ""),
	MODEM_CMD("1,CONNECT", on_cmd_connect, 0U, ""),
	MODEM_CMD("2,CONNECT", on_cmd_connect, 0U, ""),
	MODEM_CMD("3,CONNECT", on_cmd_connect, 0U, ""),
	MODEM_CMD("4,CONNECT", on_cmd_connect, 0U, ""),
	MODEM_CMD("0,CLOSED", on_cmd_closed, 0U, ""),
	MODEM_CMD("1,CLOSED", on_cmd_closed, 0U, ""),
	MODEM_CMD("2,CLOSED", on_cmd_closed, 0U, ""),
	MODEM_CMD("3,CLOSED", on_cmd_closed, 0U, ""),
	MODEM_CMD("4,CLOSED", on_cmd_closed, 0U, ""),
	MODEM_CMD("busy s...", on_cmd_busy_sending, 0U, ""),
	MODEM_CMD("busy p...", on_cmd_busy_processing, 0U, ""),
	MODEM_CMD("ready", on_cmd_ready, 0U, ""),
	MODEM_CMD_DIRECT("+IPD", on_cmd_ipd),
};

static void esp8266_mgmt_scan_work(struct k_work *work)
{
	struct esp8266_data *dev;
	int ret;
	struct modem_cmd cmds[] = {
		MODEM_CMD("+CWLAP:", on_cmd_cwlap, 4U, ","),
	};

	dev = CONTAINER_OF(work, struct esp8266_data, scan_work);

	ret = modem_cmd_send(&dev->mctx.iface, &dev->mctx.cmd_handler,
			     cmds, ARRAY_SIZE(cmds), "AT+CWLAP",
			     &dev->sem_response, ESP_SCAN_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Failed to scan: ret %d", ret);
	}

	dev->scan_cb(dev->net_iface, 0, NULL);
	dev->scan_cb = NULL;
}

static int esp8266_mgmt_scan(struct device *dev, scan_result_cb_t cb)
{
	struct esp8266_data *data = dev->driver_data;

	if (data->scan_cb != NULL) {
		return -EINPROGRESS;
	}

	if (!net_if_is_up(data->net_iface)) {
		return -EIO;
	}

	data->scan_cb = cb;

	k_work_submit_to_queue(&data->workq, &data->scan_work);

	return 0;
};

static int esp8266_mgmt_connect(struct device *dev,
				struct wifi_connect_req_params *params)
{
	char cmd[sizeof("AT+CWJAP_CUR=\"\",\"\"") + WIFI_SSID_MAX_LEN +
		 WIFI_PSK_MAX_LEN];
	struct esp8266_data *data = dev->driver_data;
	int ret, len;

	if (!net_if_is_up(data->net_iface)) {
		return -EIO;
	}

	if (esp8266_flag_is_set(data, EDF_STA_CONNECTED) ||
	    esp8266_flag_is_set(data, EDF_STA_CONNECTING)) {
		return -EALREADY;
	}

	esp8266_flag_set(data, EDF_STA_CONNECTING);

	len = snprintk(cmd, sizeof(cmd), "AT+CWJAP_CUR=\"");
	memcpy(&cmd[len], params->ssid, params->ssid_length);
	len += params->ssid_length;

	if (params->security == WIFI_SECURITY_TYPE_PSK) {
		len += snprintk(&cmd[len], sizeof(cmd) - len, "\",\"");
		memcpy(&cmd[len], params->psk, params->psk_length);
		len += params->psk_length;
	}

	len += snprintk(&cmd[len], sizeof(cmd) - len, "\"");

	ret = modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
			     NULL, 0, cmd, &data->sem_response,
			     K_NO_WAIT);

	esp8266_flag_clear(data, EDF_STA_CONNECTING);

	return ret;
}

static int esp8266_mgmt_disconnect(struct device *dev)
{
	struct esp8266_data *data = dev->driver_data;
	int ret;

	ret = modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
			     NULL, 0, "AT+CWQAP", &data->sem_response,
			     ESP_CMD_TIMEOUT);

	return ret;
}

static int esp8266_mgmt_ap_enable(struct device *dev,
				  struct wifi_connect_req_params *params)
{
	char cmd[sizeof("AT+CWSAP_CUR=\"\",\"\",xx,x") + WIFI_SSID_MAX_LEN +
		 WIFI_PSK_MAX_LEN];
	struct esp8266_data *data = dev->driver_data;
	int ecn = 0, len, ret;

	ret = modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
			     NULL, 0, "AT+CWMODE_CUR=3", &data->sem_response,
			     ESP_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Failed to enable AP mode, ret %d", ret);
		return ret;
	}

	len = snprintk(cmd, sizeof(cmd), "AT+CWSAP_CUR=\"");
	memcpy(&cmd[len], params->ssid, params->ssid_length);
	len += params->ssid_length;

	if (params->security == WIFI_SECURITY_TYPE_PSK) {
		len += snprintk(&cmd[len], sizeof(cmd) - len, "\",\"");
		memcpy(&cmd[len], params->psk, params->psk_length);
		len += params->psk_length;
		ecn = 3;
	} else {
		len += snprintk(&cmd[len], sizeof(cmd) - len, "\",\"");
	}

	snprintk(&cmd[len], sizeof(cmd) - len, "\",%d,%d", params->channel,
		 ecn);

	ret = modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
			     NULL, 0, cmd, &data->sem_response,
			     ESP_CMD_TIMEOUT);

	return ret;
}

static int esp8266_mgmt_ap_disable(struct device *dev)
{
	struct esp8266_data *data = dev->driver_data;
	int ret;

	ret = modem_cmd_send(&data->mctx.iface, &data->mctx.cmd_handler,
			     NULL, 0, "AT+CWMODE_CUR=1", &data->sem_response,
			     ESP_CMD_TIMEOUT);

	return ret;
}

static void esp8266_init_work(struct k_work *work)
{
	struct esp8266_data *dev;
	int ret;
	static struct setup_cmd setup_cmds[] = {
		/* turn off echo */
		SETUP_CMD_NOHANDLE("ATE0"),
		/* enable multiple socket support */
		SETUP_CMD_NOHANDLE("AT+CIPMUX=1"),
		SETUP_CMD_NOHANDLE("AT+CWMODE_CUR=1"),
		/* only need ecn,ssid,rssi,channel */
		SETUP_CMD_NOHANDLE("AT+CWLAPOPT=0,23"),
#if defined(CONFIG_WIFI_ESP8266_PASSIVE_TCP)
		SETUP_CMD_NOHANDLE("AT+CIPRECVMODE=1"),
#endif
		SETUP_CMD("AT+CIPSTAMAC_CUR?", "+CIPSTAMAC_CUR:",
			  on_cmd_cipstamac, 1U, ""),
	};

	dev = CONTAINER_OF(work, struct esp8266_data, init_work);

	ret = modem_cmd_handler_setup_cmds(&dev->mctx.iface,
					   &dev->mctx.cmd_handler, setup_cmds,
					   ARRAY_SIZE(setup_cmds),
					   &dev->sem_response,
					   ESP_INIT_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Init failed %d", ret);
		return;
	}

	net_if_set_link_addr(dev->net_iface, dev->mac_addr,
			     sizeof(dev->mac_addr), NET_LINK_ETHERNET);

	LOG_INF("ESP8266 Wi-Fi ready");

	net_if_up(dev->net_iface);

	k_sem_give(&dev->sem_if_up);
}

static void esp8266_reset(struct esp8266_data *dev)
{
	int ret;

	if (net_if_is_up(dev->net_iface)) {
		net_if_down(dev->net_iface);
	}

#if defined(DT_INST_0_ESPRESSIF_ESP8266_WIFI_RESET_GPIOS_PIN)
	modem_pin_write(&dev->mctx, WIFI_RESET, 0);
	k_sleep(K_MSEC(100));
	modem_pin_write(&dev->mctx, WIFI_RESET, 1);
#else
	ret = modem_cmd_send(&dev->mctx.iface, &dev->mctx.cmd_handler,
			     NULL, 0, "AT+RST", &dev->sem_response,
			     ESP_CMD_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Failed to reset device: %d", ret);
		return;
	}
#endif

	LOG_INF("Waiting for interface to come up");

	ret = k_sem_take(&dev->sem_if_up, ESP_INIT_TIMEOUT);
	if (ret == -EAGAIN) {
		LOG_ERR("Timeout waiting for interface");
	}
}

static void esp8266_iface_init(struct net_if *iface)
{
	struct device *dev = net_if_get_device(iface);
	struct esp8266_data *data = dev->driver_data;

	net_if_flag_set(iface, NET_IF_NO_AUTO_START);
	data->net_iface = iface;
	esp8266_offload_init(iface);
	esp8266_reset(data);
}

static const struct net_wifi_mgmt_offload esp8266_api = {
	.iface_api.init = esp8266_iface_init,
	.scan		= esp8266_mgmt_scan,
	.connect	= esp8266_mgmt_connect,
	.disconnect	= esp8266_mgmt_disconnect,
	.ap_enable	= esp8266_mgmt_ap_enable,
	.ap_disable	= esp8266_mgmt_ap_disable,
};

static int esp8266_init(struct device *dev)
{
	struct esp8266_data *data = dev->driver_data;
	int ret = 0;

	k_sem_init(&data->sem_tx_ready, 0, 1);
	k_sem_init(&data->sem_response, 0, 1);
	k_sem_init(&data->sem_if_up, 0, 1);

	k_work_init(&data->init_work, esp8266_init_work);
	k_delayed_work_init(&data->ip_addr_work, esp8266_ip_addr_work);
	k_work_init(&data->scan_work, esp8266_mgmt_scan_work);

	esp8266_socket_init(data);

	/* initialize the work queue */
	k_work_q_start(&data->workq, esp_workq_stack,
		       K_THREAD_STACK_SIZEOF(esp_workq_stack),
		       K_PRIO_COOP(7));

	/* cmd handler */
	data->cmd_handler_data.cmds[CMD_RESP] = response_cmds;
	data->cmd_handler_data.cmds_len[CMD_RESP] = ARRAY_SIZE(response_cmds);
	data->cmd_handler_data.cmds[CMD_UNSOL] = unsol_cmds;
	data->cmd_handler_data.cmds_len[CMD_UNSOL] = ARRAY_SIZE(unsol_cmds);
	data->cmd_handler_data.read_buf = &data->cmd_read_buf[0];
	data->cmd_handler_data.read_buf_len = sizeof(data->cmd_read_buf);
	data->cmd_handler_data.match_buf = &data->cmd_match_buf[0];
	data->cmd_handler_data.match_buf_len = sizeof(data->cmd_match_buf);
	data->cmd_handler_data.buf_pool = &mdm_recv_pool;
	data->cmd_handler_data.alloc_timeout = CMD_BUF_ALLOC_TIMEOUT;
	data->cmd_handler_data.eol = "\r\n";
	ret = modem_cmd_handler_init(&data->mctx.cmd_handler,
				       &data->cmd_handler_data);
	if (ret < 0) {
		goto error;
	}

	/* modem interface */
	data->iface_data.isr_buf = &data->iface_isr_buf[0];
	data->iface_data.isr_buf_len = sizeof(data->iface_isr_buf);
	data->iface_data.rx_rb_buf = &data->iface_rb_buf[0];
	data->iface_data.rx_rb_buf_len = sizeof(data->iface_rb_buf);
	ret = modem_iface_uart_init(&data->mctx.iface, &data->iface_data,
				    WIFI_UART_DEV_NAME);
	if (ret < 0) {
		goto error;
	}

	/* pin setup */
	data->mctx.pins = modem_pins;
	data->mctx.pins_len = ARRAY_SIZE(modem_pins);

	data->mctx.driver_data = data;

	ret = modem_context_register(&data->mctx);
	if (ret < 0) {
		LOG_ERR("Error registering modem context: %d", ret);
		goto error;
	}

	/* start RX thread */
	k_thread_create(&esp_rx_thread, esp_rx_stack,
			K_THREAD_STACK_SIZEOF(esp_rx_stack),
			(k_thread_entry_t)esp8266_rx,
			dev, NULL, NULL, K_PRIO_COOP(7), 0, K_NO_WAIT);

error:
	return ret;
}

NET_DEVICE_OFFLOAD_INIT(wifi_esp8266, CONFIG_WIFI_ESP8266_NAME,
			esp8266_init, &esp8266_driver_data, NULL,
			CONFIG_WIFI_INIT_PRIORITY, &esp8266_api,
			ESP8266_MTU);
