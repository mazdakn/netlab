#include "packet.h"



// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum (uint16_t *addr, int len)
{	
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1) {
		sum += *(addr++);
		count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0) {
		sum += *(uint8_t *) addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;
	return (answer);
}



void randomPayload (uint8_t *payload, int length)
{
    int i = 0;
	char charset[] = "0123456789abcdefghijklmnopqrstuvwxyz";
	int max_index = sizeof(charset) - 1;

	for (i=0; i< length; i++)
		payload[i] = charset[ rand() %  max_index];
}

void dumpPacket(const unsigned char *buffer, const unsigned int length)
{
	unsigned char byte;
    unsigned int i, j;

    printf ("\n");

    for (i=0; i<length;i++) {
		byte = buffer[i];
        printf ("%02x ", byte);

        if (((i % 16)==15) || (i==length-1)) {
			for (j=0; j< 15-(i%16); j++)
				printf ("   ");

            printf ("| ");

            for (j=(i-(i%16)); j<=i ; j++) {
				byte = buffer[j];
                if ((byte > 31) && (byte < 127))
					printf ("%c",byte);
                else
					printf (".");
            }

            printf ("\n");
        }
    }

	printf ("\n\n");
}

