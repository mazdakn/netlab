#include <stdlib.h>
#include <stdio.h>
#include <bpf.h>
#include <libbpf.h>
#include <errno.h>
#include <string.h>

#define PACKET_MAX_SIZE 2000

void print_packet(const char *message, const unsigned char *packet, int size) {
	printf("%s(size=%d): ", message, size);
	for (int i = 0; i <  size; i++) {
		printf("%02x ", packet[i]);
	}

	printf("\n");
}

int main(int argc, char **argv) {
	unsigned char udp_packet[] = {
					0x52, 0x54, 0x00, 0x5c, 0x54, 0xec, 0x52, 0x54,
		 			0x00, 0xe6, 0xf4, 0x2e, 0x08, 0x00, 0x45, 0x00,
					0x00, 0x1e, 0x0d, 0xb2, 0x40, 0x00, 0x40, 0x11,
					0x17, 0xd8, 0x0a, 0x59, 0x80, 0x01, 0x0a, 0x59,
					0x80, 0x92, 0xd5, 0x8c, 0x1f, 0x40, 0x00, 0x0a,
					0x15, 0x61, 0x41, 0x0a};	

	unsigned char tcp_packet[] = {
					0x52, 0x54, 0x00, 0x5c, 0x54, 0xec, 0x52, 0x54,
					0x00, 0xe6, 0xf4, 0x2e, 0x08, 0x00, 0x45, 0x00,
					0x00, 0x3c, 0x62, 0xcc, 0x40, 0x00, 0x40, 0x06,
					0xc2, 0xaa, 0x0a, 0x59, 0x80, 0x01, 0x0a, 0x59,
					0x80, 0x92, 0x95, 0x20, 0x00, 0x16, 0x9b, 0xe9,
					0xef, 0x30, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
					0xfa, 0xf0, 0x15, 0x74, 0x00, 0x00, 0x02, 0x04,
					0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x1c, 0x37,
					0xeb, 0x43, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
					0x03, 0x07};

	char *filename, *section;
	int prog_fd;
	struct bpf_object *obj;
	int repeat;
	char packet_out[PACKET_MAX_SIZE];
	__u32 retval, duration;
	__u32 packet_size = 0;

	if (argc < 4) {
		printf("%s <filename> <section> <repeat>\n", argv[0]);
		return -1;
	}

	filename = argv[1];
	section  = argv[2];
	repeat   = atoi(argv[3]);

	printf("Filename: %s - Section: %s - Repeat %d\n", filename, section, repeat);

	__builtin_memset(packet_out, 0, PACKET_MAX_SIZE);
	
	if (bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd) != 0) {
		printf("cound not load XDP program\n");
		return -1;
	}

	if (prog_fd < 1) {
		printf("Error creating prog_fd\n");
		return -1;
	}

	bpf_object__find_program_by_name(obj, section);


	printf("=== Testing with TCP packet ===\n");
	print_packet("Packet in", (unsigned char *)&tcp_packet, sizeof(tcp_packet));

	int ret = bpf_prog_test_run(prog_fd, repeat, &tcp_packet, sizeof(tcp_packet),
			&packet_out, &packet_size, &retval, &duration);
	if (ret) {
		printf("Error running the test: %d\n", ret);
		return -1;
	}

	print_packet("Packet out", (unsigned char *)&packet_out, packet_size);
	printf("Repeat: %d - Retval: %d - Duration %d\n", repeat, retval, duration);


	printf("=== Testing with UDP packet ===\n");
	print_packet("Packet in", (unsigned char *)&udp_packet, sizeof(udp_packet));

	ret = bpf_prog_test_run(prog_fd, repeat, &udp_packet, sizeof(udp_packet),
			&packet_out, &packet_size, &retval, &duration);
	if (ret) {
		printf("Error running the test: %d\n", ret);
		return -1;
	}

	print_packet("Packet out", (unsigned char *)&packet_out, packet_size);
	printf("Repeat: %d - Retval: %d - Duration %d\n", repeat, retval, duration);

	return 0;
}
