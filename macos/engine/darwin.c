#define _GNU_SOURCE

#include "darwin.h"
#include "checksum.h"
#include "params.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define DARWIN_BUFFER_SIZE (512 * 1024)
#define DARWIN_FRAME_SIZE (65535 + 14)
#define PF_IN 1

struct darwin_pfloghdr {
	uint8_t length;
	uint8_t af;
	uint8_t action;
	uint8_t reason;
	char ifname[IFNAMSIZ];
	char ruleset[16];
	uint32_t rulenr;
	uint32_t subrulenr;
	uint32_t uid;
	uint32_t pid;
	uint32_t rule_uid;
	uint32_t rule_pid;
	uint8_t dir;
	uint8_t pad[3];
};

static struct {
	int capture_fd;
	int sender_fd;
	char interface[IFNAMSIZ];
	uint8_t source_mac[6];
	uint8_t gateway_mac[6];
	int mtu;
	uint8_t buffer[DARWIN_BUFFER_SIZE] __attribute__((aligned));
	size_t buffered;
	size_t offset;
	uint8_t frame[DARWIN_FRAME_SIZE];
} transport = { .capture_fd = -1, .sender_fd = -1 };

static bool valid_name(const char *value)
{
	if (!value || !*value || strlen(value) >= IFNAMSIZ) return false;
	for (const uint8_t *p = (const uint8_t *)value; *p; p++)
		if (!isalnum(*p) && *p != '_' && *p != '-' && *p != '.') return false;
	return true;
}

static bool read_mac(const char *value, uint8_t mac[6])
{
	unsigned int parts[6];
	char tail;
	if (!value || sscanf(value, "%x:%x:%x:%x:%x:%x%c", &parts[0], &parts[1],
		&parts[2], &parts[3], &parts[4], &parts[5], &tail) != 6) return false;
	for (int i = 0; i < 6; i++)
	{
		if (parts[i] > 255) return false;
		mac[i] = (uint8_t)parts[i];
	}
	return true;
}

static int open_bpf(const char *interface, int buffer_size, int expected_dlt, bool sender)
{
	int fd = -1;
	for (int number = 0; number < 256; number++)
	{
		char device[32];
		snprintf(device, sizeof(device), "/dev/bpf%d", number);
		fd = open(device, O_RDWR);
		if (fd >= 0) break;
		if (errno == ENOENT || errno == EACCES || errno == EPERM) return -1;
	}
	if (fd < 0) return -1;

	struct ifreq request;
	memset(&request, 0, sizeof(request));
	strlcpy(request.ifr_name, interface, sizeof(request.ifr_name));
	if (ioctl(fd, BIOCSBLEN, &buffer_size) < 0 || ioctl(fd, BIOCSETIF, &request) < 0)
		goto failed;

	int one = 1, zero = 0, dlt = 0;
	if (ioctl(fd, BIOCIMMEDIATE, &one) < 0 || ioctl(fd, BIOCSSEESENT, &zero) < 0 ||
		(sender && ioctl(fd, BIOCSHDRCMPLT, &one) < 0) || ioctl(fd, BIOCGDLT, &dlt) < 0 ||
		dlt != expected_dlt || fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) < 0)
		goto failed;
	return fd;
failed:
	close(fd);
	return -1;
}

static bool read_configuration(void)
{
	const char *interface = getenv("IGARECK_DARWIN_IFACE");
	const char *pflog = getenv("IGARECK_DARWIN_PFLOG");
	const char *mtu = getenv("IGARECK_DARWIN_MTU");
	if (!valid_name(interface) || !valid_name(pflog) || strncmp(pflog, "pflog", 5) ||
		!read_mac(getenv("IGARECK_DARWIN_SRC_MAC"), transport.source_mac) ||
		!read_mac(getenv("IGARECK_DARWIN_DST_MAC"), transport.gateway_mac))
	{
		DLOG_ERR("darwin: invalid transport environment\n");
		return false;
	}
	strlcpy(transport.interface, interface, sizeof(transport.interface));
	transport.mtu = mtu ? atoi(mtu) : 1500;
	if (transport.mtu < 576 || transport.mtu > 65535)
	{
		DLOG_ERR("darwin: invalid MTU\n");
		return false;
	}
	return true;
}

bool darwin_capture_init(void)
{
	if (!read_configuration()) return false;
	const char *pflog = getenv("IGARECK_DARWIN_PFLOG");
	transport.capture_fd = open_bpf(pflog, DARWIN_BUFFER_SIZE, DLT_PFLOG, false);
	if (transport.capture_fd < 0)
	{
		DLOG_PERROR("darwin: open pflog BPF");
		return false;
	}
	transport.buffered = transport.offset = 0;
	return true;
}

bool darwin_sender_init(void)
{
	if (transport.sender_fd >= 0) return true;
	if (!*transport.interface && !read_configuration()) return false;
	transport.sender_fd = open_bpf(transport.interface, 32768, DLT_EN10MB, true);
	if (transport.sender_fd < 0)
	{
		DLOG_PERROR("darwin: open Ethernet BPF");
		return false;
	}
	return true;
}

static const uint8_t *next_record(size_t *length, bool *incoming)
{
	while (transport.offset < transport.buffered)
	{
		size_t left = transport.buffered - transport.offset;
		if (left < sizeof(struct bpf_hdr)) break;
		struct bpf_hdr header;
		memcpy(&header, transport.buffer + transport.offset, sizeof(header));
		size_t header_length = header.bh_hdrlen;
		size_t captured = header.bh_caplen;
		if (header_length < sizeof(header) || captured < 1 || header_length + captured > left) break;
		const uint8_t *frame = transport.buffer + transport.offset + header_length;
		transport.offset += BPF_WORDALIGN(header_length + captured);
		size_t ip_offset = BPF_WORDALIGN(frame[0]);
		if (ip_offset >= captured) continue;
		const uint8_t *packet = frame + ip_offset;
		uint8_t version = packet[0] >> 4;
		if (version != 4 && version != 6) continue;
		*length = captured - ip_offset;
		*incoming = frame[0] >= offsetof(struct darwin_pfloghdr, pad) &&
			frame[offsetof(struct darwin_pfloghdr, dir)] == PF_IN;
		return packet;
	}
	transport.buffered = transport.offset = 0;
	return NULL;
}

const uint8_t *darwin_recv(size_t *length, bool *incoming)
{
	errno = 0;
	const uint8_t *packet = next_record(length, incoming);
	if (packet) return packet;
	for (;;)
	{
		fd_set readers;
		FD_ZERO(&readers);
		FD_SET(transport.capture_fd, &readers);
		struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
		int ready = select(transport.capture_fd + 1, &readers, NULL, NULL, &timeout);
		if (ready < 0) return NULL;
		if (!ready)
		{
			errno = EAGAIN;
			return NULL;
		}
		ssize_t result = read(transport.capture_fd, transport.buffer, sizeof(transport.buffer));
		if (result < 0 && (errno == EINTR || errno == EAGAIN)) return NULL;
		if (result == 0) errno = EIO;
		if (result <= 0) return NULL;
		transport.buffered = (size_t)result;
		transport.offset = 0;
		packet = next_record(length, incoming);
		if (packet) return packet;
	}
}

static bool write_frame(const uint8_t *packet, size_t length)
{
	if (!length || length > 65535) return false;
	size_t frame_length = length + 14;
	size_t padded = frame_length < 60 ? 60 : frame_length;
	memcpy(transport.frame, transport.gateway_mac, 6);
	memcpy(transport.frame + 6, transport.source_mac, 6);
	uint16_t type = htons((packet[0] >> 4) == 6 ? 0x86dd : 0x0800);
	memcpy(transport.frame + 12, &type, 2);
	memcpy(transport.frame + 14, packet, length);
	if (padded > frame_length) memset(transport.frame + frame_length, 0, padded - frame_length);
	ssize_t written;
	do written = write(transport.sender_fd, transport.frame, padded); while (written < 0 && errno == EINTR);
	if (written != (ssize_t)padded)
	{
		DLOG_PERROR("darwin: BPF write");
		return false;
	}
	return true;
}

bool darwin_send(const void *data, size_t length)
{
	const uint8_t *packet = data;
	if (length <= (size_t)transport.mtu) return write_frame(packet, length);
	if (length < 20 || packet[0] >> 4 != 4) return false;

	struct ip header;
	memcpy(&header, packet, sizeof(header));
	size_t header_length = header.ip_hl << 2;
	if (header_length < 20 || header_length > length) return false;
	size_t offset = 0;
	while (offset < length - header_length)
	{
		size_t remaining = length - header_length - offset;
		size_t chunk = remaining;
		if (header_length + chunk > (size_t)transport.mtu)
			chunk = ((size_t)transport.mtu - header_length) & ~7U;
		if (!chunk) return false;
		uint8_t fragment[65535];
		memcpy(fragment, packet, header_length);
		memcpy(fragment + header_length, packet + header_length + offset, chunk);
		struct ip *ip = (struct ip *)fragment;
		ip->ip_len = htons(header_length + chunk);
		uint16_t flags = ntohs(ip->ip_off) & 0x8000;
		flags |= (uint16_t)(offset / 8);
		if (offset + chunk < length - header_length) flags |= IP_MF;
		ip->ip_off = htons(flags);
		ip4_fix_checksum(ip);
		if (!write_frame(fragment, header_length + chunk)) return false;
		offset += chunk;
	}
	return true;
}

const char *darwin_interface(void)
{
	return transport.interface;
}

void darwin_transport_cleanup(void)
{
	if (transport.capture_fd >= 0) close(transport.capture_fd);
	if (transport.sender_fd >= 0) close(transport.sender_fd);
	transport.capture_fd = transport.sender_fd = -1;
}
