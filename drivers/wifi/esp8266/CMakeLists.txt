# SPDX-License-Identifier: Apache-2.0

if(CONFIG_WIFI_ESP8266)
  zephyr_include_directories(./)

  zephyr_library_include_directories(
    ${ZEPHYR_BASE}/drivers/modem
  )

  zephyr_sources(
    esp8266.c
    esp8266_socket.c
    esp8266_offload.c
  )
endif()
