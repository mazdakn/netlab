#include "flow.h"

// list of packet is implemented by a circular linked list

// insert a packet
struct packet_list_type *insertPacket(struct packet_list_type *head, u_int32_t packetSeq, u_int32_t packetLen)
{
	struct packet_list_type *ptr=NULL;

	// memory allocation
	if ((ptr=malloc(sizeof(struct packet_list_type)))==NULL)
	{
		perror ("memory allocation error\n");
		exit(EXIT_FAILURE);
	}

	ptr->next=head;
	ptr->prev=head->prev;
	head->prev->next=ptr;
	head->prev=ptr;

       	ptr->len=packetLen;
       	ptr->seq=packetSeq;

	return ptr;
}

// delete a packet
void deletePacket (struct packet_list_type *packet)
{
	packet->prev->next=packet->next;
	packet->next->prev=packet->prev;

	free(packet);
}

//delte all packets
void deleteAllPackets (struct packet_list_type *head)
{
	struct packet_list_type *ptr=head->next;

	while (ptr!=head)
	{
		ptr=ptr->next;
		free(ptr->prev);
	}

	ptr->next=head;
	ptr->prev=head;
}

//search a packet in linked list
struct packet_list_type *searchPacket(struct packet_list_type *head, u_int32_t packetSeq)
{
	struct packet_list_type *ptr=head->prev;

	while (ptr!=head)
	{
		if (ptr->seq==packetSeq)
		{
			return ptr;
		}

		ptr=ptr->prev;
	}

	return NULL;
}
