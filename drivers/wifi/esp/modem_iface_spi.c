/** @file
 * @brief interface for modem context
 *
 * UART-based modem interface implementation for modem context driver.
 */

/*
 * Copyright (c) 2019 Foundries.io
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(modem_iface_spi, CONFIG_MODEM_LOG_LEVEL);

#include <kernel.h>
#include <drivers/spi.h>
#include <drivers/gpio.h>

#include "modem_context.h"
#include "modem_iface_spi.h"

static u8_t rxbuf[1];
static u8_t txbuf[1];

static struct spi_buf rx_spi_buf = {
	.buf = rxbuf,
	.len = sizeof(rxbuf),
};

static struct spi_buf_set rx_spi_buf_set = {
	.buffers = &rx_spi_buf,
	.count = 1,
};

static struct spi_buf tx_spi_buf = {
	.buf = txbuf,
};

static struct spi_buf_set tx_spi_buf_set = {
	.buffers = &tx_spi_buf,
	.count = 1,
};

static struct spi_config spi_cfg;

static void wait_for_handshake(struct device *gpio_dev)
{
	while (gpio_pin_get(gpio_dev, 10) == 0);
}

static void send_tx_hdr(struct modem_iface *iface)
{
	tx_spi_buf.buf = "\x02\x00\x00\x00";
	tx_spi_buf.len = 4;
	spi_write(iface->dev, &spi_cfg, &tx_spi_buf_set);
}

static void send_tx_len(struct modem_iface *iface, size_t len)
{
	u8_t len_buf[] = { len & 0x7f, len >> 7, 0, 'A' };
	/*
	printk("len_buf: %x\n", len_buf[0]);
	printk("len_buf: %x\n", len_buf[1]);
	printk("len_buf: %x\n", len_buf[2]);
	printk("len_buf: %x\n", len_buf[3]);
	*/

	tx_spi_buf.buf = len_buf;
	tx_spi_buf.len = 4;
	spi_write(iface->dev, &spi_cfg, &tx_spi_buf_set);
}

static void send_rx_hdr(struct modem_iface *iface)
{
	rx_spi_buf.buf = "\x01\x00\x00\x00";
	rx_spi_buf.len = 4;
	spi_write(iface->dev, &spi_cfg, &rx_spi_buf_set);
}

static void recv_rx_len(struct modem_iface *iface, size_t *len)
{
	u8_t len_buf[4];

	rx_spi_buf.buf = len_buf;
	rx_spi_buf.len = 4;
	spi_read(iface->dev, &spi_cfg, &rx_spi_buf_set);

	*len = len_buf[0] + (len_buf[1] << 7);
	/*
	printk("len_buf: %x\n", len_buf[0]);
	printk("len_buf: %x\n", len_buf[1]);
	printk("len_buf: %x\n", len_buf[2]);
	printk("len_buf: %x\n", len_buf[3]);
	*/
}

/**
 * @brief  Drains UART.
 *
 * @note   Discards remaining data.
 *
 * @param  *iface: modem interface.
 *
 * @retval None.
 */
#if 0
static void modem_iface_uart_flush(struct modem_iface *iface)
{
	u8_t c;

	while (uart_fifo_read(iface->dev, &c, 1) > 0) {
		continue;
	}
}
#endif
/**
 * @brief  Modem interface interrupt handler.
 *
 * @note   Fills interfaces ring buffer with received data.
 *         When ring buffer is full the data is discarded.
 *
 * @param  *uart_dev: uart device.
 *
 * @retval None.
 */
#if 0
static void modem_iface_uart_isr(struct device *uart_dev)
{
	struct modem_context *ctx;
	struct modem_iface_uart_data *data;
	int rx = 0, ret;

	/* lookup the modem context */
	ctx = modem_context_from_iface_dev(uart_dev);
	if (!ctx || !ctx->iface.iface_data) {
		return;
	}

	data = (struct modem_iface_uart_data *)(ctx->iface.iface_data);
	/* get all of the data off UART as fast as we can */
	while (uart_irq_update(ctx->iface.dev) &&
	       uart_irq_rx_ready(ctx->iface.dev)) {
		rx = uart_fifo_read(ctx->iface.dev,
				    data->isr_buf, data->isr_buf_len);
		if (rx <= 0) {
			continue;
		}

		ret = ring_buf_put(&data->rx_rb, data->isr_buf, rx);
		if (ret != rx) {
			LOG_ERR("Rx buffer doesn't have enough space. "
				"Bytes pending: %d, written: %d",
				rx, ret);
			modem_iface_uart_flush(&ctx->iface);
			k_sem_give(&data->rx_sem);
			break;
		}

		k_sem_give(&data->rx_sem);
	}
}
#endif

static void handshake_interrupt(struct device *dev, struct gpio_callback *cb,
				u32_t pin_pos)
{
	struct modem_iface_spi_data *data;

	data = CONTAINER_OF(cb, struct modem_iface_spi_data,
			    handshake_gpio_cb);

	//printk("give sem\n");
	k_sem_give(&data->rx_sem);
	//k_sleep(K_MSEC(100));
	//gpio_disable_callback(data->handshake_gpio_dev, 10);
	//gpio_enable_callback(data->handshake_gpio_dev, 10);
	/*
	gpio_pin_interrupt_configure(data->handshake_gpio_dev, 10,
				     GPIO_INT_DISABLE);
	*/
}

static int modem_iface_spi_read(struct modem_iface *iface,
				 u8_t *buf, size_t size, size_t *bytes_read)
{
	struct modem_iface_spi_data *data;
	size_t len;

	if (!iface || !iface->iface_data) {
		return -EINVAL;
	}

	if (size == 0) {
		*bytes_read = 0;
		return 0;
	}

	data = (struct modem_iface_spi_data *)(iface->iface_data);

	if (gpio_pin_get(data->handshake_gpio_dev, 10) == 0) {
		*bytes_read = 0;
		return 0;
	}

/*
	gpio_pin_interrupt_configure(data->handshake_gpio_dev, 10,
				     GPIO_INT_DISABLE);
*/
	send_rx_hdr(iface);
	wait_for_handshake(data->handshake_gpio_dev);
	recv_rx_len(iface, &len);
	//wait_for_handshake(data->handshake_gpio_dev);

	rx_spi_buf.buf = buf;
	rx_spi_buf.len = MIN(size, len);
	spi_read(iface->dev, &spi_cfg, &rx_spi_buf_set);

	*bytes_read = rx_spi_buf.len;
		//ring_buf_get(&data->rx_rb, buf, size);

/*
	gpio_pin_interrupt_configure(data->handshake_gpio_dev, 10,
				     GPIO_INT_LEVEL_HIGH);
*/
	return 0;
}

static int modem_iface_spi_write(struct modem_iface *iface,
				  const u8_t *buf, size_t size)
{
	struct modem_iface_spi_data *data;

	if (!iface || !iface->iface_data) {
		return -EINVAL;
	}

	if (size == 0) {
		return 0;
	}

	data = (struct modem_iface_spi_data *)(iface->iface_data);
/*
	gpio_pin_interrupt_configure(data->handshake_gpio_dev, 10,
				     GPIO_INT_DISABLE);
*/

	send_tx_hdr(iface);
	wait_for_handshake(data->handshake_gpio_dev);
	send_tx_len(iface, size);
	wait_for_handshake(data->handshake_gpio_dev);

	tx_spi_buf.buf = buf;
	tx_spi_buf.len = size;
	spi_write(iface->dev, &spi_cfg, &tx_spi_buf_set);
	//wait_for_handshake(data->handshake_gpio_dev);
	//
	if (buf[0] == '\r' && buf[1] == '\n') {
		wait_for_handshake(data->handshake_gpio_dev);
	}
/*
	gpio_pin_interrupt_configure(data->handshake_gpio_dev, 10,
				     GPIO_INT_LEVEL_LOW);
*/
	//printk("Int enabled\n");

	return 0;
}

int modem_iface_spi_init_dev(struct modem_iface *iface,
			      const char *dev_name)
{
	/* get UART device */
	iface->dev = device_get_binding(dev_name);
	if (!iface->dev) {
		return -ENODEV;
	}

	//uart_irq_rx_disable(iface->dev);
	//uart_irq_tx_disable(iface->dev);
	//modem_iface_uart_flush(iface);
	//uart_irq_callback_set(iface->dev, modem_iface_uart_isr);
	//uart_irq_rx_enable(iface->dev);

	return 0;
}

int modem_iface_spi_init(struct modem_iface *iface,
			  struct modem_iface_spi_data *data,
			  const char *dev_name)
{
	int ret;

	if (!iface || !data) {
		return -EINVAL;
	}

	iface->iface_data = data;
	iface->read = modem_iface_spi_read;
	iface->write = modem_iface_spi_write;

	data->handshake_gpio_dev = device_get_binding("gpio_0");
	gpio_pin_configure(data->handshake_gpio_dev, 10, GPIO_INPUT);
	gpio_pin_interrupt_configure(data->handshake_gpio_dev, 10, GPIO_INT_EDGE_RISING);
	gpio_init_callback(&data->handshake_gpio_cb, handshake_interrupt, BIT(10));
	gpio_add_callback(data->handshake_gpio_dev, &data->handshake_gpio_cb);
	gpio_enable_callback(data->handshake_gpio_dev, 10);

	spi_cfg.frequency = 80000;
	spi_cfg.operation = SPI_OP_MODE_MASTER | SPI_WORD_SET(8);
	spi_cfg.slave = 2;
	spi_cfg.cs = NULL;

	ring_buf_init(&data->rx_rb, data->rx_rb_buf_len, data->rx_rb_buf);
	k_sem_init(&data->rx_sem, 0, 1);

	/* get UART device */
	ret = modem_iface_spi_init_dev(iface, dev_name);
	if (ret < 0) {
		iface->iface_data = NULL;
		iface->read = NULL;
		iface->write = NULL;

		return ret;
	}

	return 0;
}
