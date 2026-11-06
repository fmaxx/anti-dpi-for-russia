#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool darwin_capture_init(void);
bool darwin_sender_init(void);
const uint8_t *darwin_recv(size_t *length, bool *incoming);
bool darwin_send(const void *data, size_t length);
const char *darwin_interface(void);
void darwin_transport_cleanup(void);
