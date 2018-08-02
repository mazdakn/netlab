#include "flow.h"

// search a packet in DS to find a related flow
struct flow_list_bst_type *searchFlowBST(struct flow_list_bst_head_type *flowList, struct packet_type *packet)
{
	struct flow_list_bst_type *ptr = flowList->head; // current node. search starting head
	struct flow_list_bst_type *ptrDel = NULL; // pointer for timers

	flowList->head->flow.time_sec=packet->time_sec; //update head time info, so timers do not delete it!

	// first search to find flow for this packet, with assumption that
	// packet is compatible with direct path of flow
	while (ptr!=NULL)
	{
		// Timers

		// timer1:
		// if flow state is still in 3-way handshaking, and if after BIRECTIONAL_FLOW_PERIOD, which is 30 sec
		// by default, the expected packet has not been seen, delete flow
                if ((ptr->flow.state.value==SYN) || (ptr->flow.state.value==SYN+ACK))
        	{
                	if (packet->time_sec-(ptr->flow.time_sec) > BIDIRECTIONAL_FLOW_PERIOD)
                       {
	              		flowList->procStat.handshakeStaleFlowCounter++;
				ptrDel=ptr->parent;
                               	deleteFlowBST(ptr);
				ptr=ptrDel;
				continue;
                        }
                }
		else
		// timer 2:
		// in other flow states, if no new packet has been seen for this flow for STALE_PERIOD time, which is 120 sec
		// delete it
		{
			if (packet->time_sec-(ptr->flow.time_sec) > STALE_PERIOD)
                	{
	              		flowList->procStat.staleFlowCounter++;
                               	ptrDel=ptr->parent;
                                deleteFlowBST(ptr);
                                ptr=ptrDel;
                               	continue;
                	}
		}

		// check if this flow for the packet
		if (((packet->node1.hash==ptr->flow.node1.hash) && (packet->node2.hash==ptr->flow.node2.hash)))
			//|| ((packet->node1.hash==ptr->flow.node2.hash) && (packet->node2.hash==ptr->flow.node1.hash)))
		{
			return ptr;
		}

		// first check hash2
		// no esp. difference if we first check hash1

		// traverse tree based on hash2

		// if packet.hash2 > flow.hash2 go to right
		if (packet->node2.hash > ptr->flow.node2.hash)
		{
			ptr=ptr->right;
			continue;
		}

		// if packet.hash2 < flow.hash2 go to left
		if (packet->node2.hash < ptr->flow.node2.hash)
                {
	             	ptr=ptr->left;
                       	continue;
               	}

		// in this point, packet.hash2 == flow.hash2
		// traverse tree based on hash1

		// if packet.hash2 > flow.hash2 go to right
                if (packet->node1.hash > ptr->flow.node1.hash)
                {
		        ptr=ptr->right;
                       	continue;
                }

		// if packet.hash2 > flow.hash2 go to right
                if (packet->node1.hash < ptr->flow.node1.hash)
                {
                       	ptr=ptr->left;
                       	continue;
                }

		// in this point, packet.hash2 == flow.hash2
		// and packet.hash1 == flow.hash1
	}

	// if function reaches this point, it show either assumption about packet direction is wrong or
	// packet belongs to no related flow
	// but another search with assumption that packet belogns to reverse dirction should be happen

	// do search with assumption that packet is a reverse packet
        ptr = flowList->head;

        while (ptr!=NULL)
        {
		// timer 1
                if ((ptr->flow.state.value==SYN) || (ptr->flow.state.value==SYN+ACK))
                {
                        if (packet->time_sec-(ptr->flow.time_sec) > BIDIRECTIONAL_FLOW_PERIOD)
                        {
	              		flowList->procStat.handshakeStaleFlowCounter++;
                                ptrDel=ptr->parent;
                                deleteFlowBST(ptr);
                                ptr=ptrDel;
                                continue;
                        }
                }
		// timer 2
                else
                {
                        if (packet->time_sec-(ptr->flow.time_sec) > STALE_PERIOD)
                        {
                               	flowList->procStat.staleFlowCounter++;
                               	ptrDel=ptr->parent;
                                deleteFlowBST(ptr);
                               	ptr=ptrDel;
                                continue;
                        }
               	}

		// compare packet with flow
                //if (((packet->node1.hash==ptr->flow.node1.hash) && (packet->node2.hash==ptr->flow.node2.hash)) ||
                if  (((packet->node1.hash==ptr->flow.node2.hash) && (packet->node2.hash==ptr->flow.node1.hash)))
                {
                        return ptr;
                }

		// traverse tree based on hash1

                if (packet->node1.hash > ptr->flow.node2.hash)
                {
                        ptr=ptr->right;
                        continue;
                }

                if (packet->node1.hash < ptr->flow.node2.hash)
                {
                        ptr=ptr->left;
                        continue;
                }

		// packet.hash1 == flow.hash1

		// traverse tree based on hash2

                if (packet->node2.hash > ptr->flow.node1.hash)
                {
                        ptr=ptr->right;
                        continue;
                }

                if (packet->node2.hash < ptr->flow.node1.hash)
                {
                        ptr=ptr->left;
                        continue;
                }
        }

	// if function reaches this point, we can be sure that no flow has been created for this packet

	return NULL;
}


// insert a flow to DS
struct flow_list_bst_type *insertFlowBST(struct flow_list_bst_head_type *flowList,struct packet_type *packet)
{
        struct flow_list_bst_type *ptr = flowList->head; // current node
	struct flow_list_bst_type *ptrDel = NULL; // pointer for timers
	struct flow_list_bst_type *parent = NULL; // pointer to parent of current node

	// to keep track of parent and which child of parent is current child
	int parentChild=0;
	const int RIGHTCHILD=1;
	const int LEFTCHILD=2;

	flowList->head->flow.time_sec=packet->time_sec;

	// search DS until reach NULL pointer
	// we have to keep track of nodes parent

        while (ptr!=NULL)
        {
		// timer 1
                if ((ptr->flow.state.value==SYN) || (ptr->flow.state.value==SYN+ACK))
                {
                        if (packet->time_sec-(ptr->flow.time_sec) > BIDIRECTIONAL_FLOW_PERIOD)
                        {
	              		flowList->procStat.handshakeStaleFlowCounter++;
                                ptrDel=ptr->parent;
                                deleteFlowBST(ptr);
                                ptr=ptrDel;
                                continue;
                        }
                }
                else
		// timer 2
                {
                        if (packet->time_sec-(ptr->flow.time_sec) > STALE_PERIOD)
                        {
                                flowList->procStat.staleFlowCounter++;
                                ptrDel=ptr->parent;
                                deleteFlowBST(ptr);
                                ptr=ptrDel;
                                continue;
                        }
                }

		// insert packet based on hash2

		// travers tree based on packet.hash2

                if (packet->node2.hash > ptr->flow.node2.hash)
                {
			parent=ptr;
                       	ptr=ptr->right;
			parentChild=RIGHTCHILD; // right child of parent
                       	continue;
                }

                if (packet->node2.hash < ptr->flow.node2.hash)
                {
			parent=ptr;
                       	ptr=ptr->left;
			parentChild=LEFTCHILD; // left child of parent
                        continue;
                }

		// packet.hash2 == flow.hash2

		//travers based on hash1

                if (packet->node1.hash > ptr->flow.node1.hash)
                {
			parent=ptr;
                        ptr=ptr->right;
       			parentChild=RIGHTCHILD; // right child of parent
	                continue;
                }

                if (packet->node1.hash < ptr->flow.node1.hash)
                {
			parent=ptr;
                        ptr=ptr->left;
			parentChild=LEFTCHILD; // left child of parent
                        continue;
                }

		//this situation should never happen
		showPacketBST(flowList,packet);
	     	fprintf (stderr,"[***] This should not happen!!: ");
              	exit(EXIT_FAILURE);
        }

	// create new flow
	if ((ptr=malloc(sizeof(struct flow_list_bst_type)))==NULL)
	{
		perror("Error in allocating memory:");
		exit(EXIT_FAILURE);
	}

	if (memset(ptr,0,sizeof(struct flow_list_bst_type))!=ptr) // initialize the node
	{
		perror("setting memory:");
		exit(EXIT_FAILURE);
	}

	if (parentChild==RIGHTCHILD)
	{
		parent->right=ptr;
	}
	else
	{
		parent->left=ptr;
	}

	ptr->parent=parent;
	ptr->right=NULL;
	ptr->left=NULL;

	// update ip and port
	ptr->flow.node1.hash=NIL;
	ptr->flow.node1.info.ip=packet->node1.info.ip;
        ptr->flow.node1.info.port=packet->node1.info.port;

	ptr->flow.node2.hash=NIL;
        ptr->flow.node2.info.ip=packet->node2.info.ip;
        ptr->flow.node2.info.port=packet->node2.info.port;

	// update time
        ptr->flow.time_sec=packet->time_sec;
        ptr->flow.time_usec=packet->time_usec;

	ptr->flow.state.value=SYN; // set flow state

	// creat memory for list of packets
        if ((ptr->flow.session1.head=malloc(sizeof(struct packet_list_type)))==NULL)
        {
                perror("memory allocation");
                exit(EXIT_FAILURE);
        }

	ptr->flow.session1.head->len=NIL;
        ptr->flow.session1.head->seq=NIL;
        ptr->flow.session1.head->next=ptr->flow.session1.head;
        ptr->flow.session1.head->prev=ptr->flow.session1.head;

        if ((ptr->flow.session2.head=malloc(sizeof(struct packet_list_type)))==NULL)
        {
                perror("memory allocation");
                exit(EXIT_FAILURE);
        }

	ptr->flow.session2.head->len=NIL;
        ptr->flow.session2.head->seq=NIL;
        ptr->flow.session2.head->next=ptr->flow.session2.head;
        ptr->flow.session2.head->prev=ptr->flow.session2.head;

	return ptr;
}

// delete a flow in DS
void deleteFlowBST(struct flow_list_bst_type *flow)
{
	// if node has no child
	// it's simplest scenario
	if ((flow->right==NULL) && (flow->left==NULL))
        {
               	if (flow->parent->right==flow)
		{
			flow->parent->right=NULL;
		}
		else
		{
			flow->parent->left=NULL;
		}

		free(flow);
                return;
    	}

	// if right child is empty
	if (flow->right==NULL) // left
	{
		if (flow == flow->parent->right) // right
		{
			flow->parent->right=flow->left;
			flow->left->parent=flow->parent;
			free(flow);
			return;
		}
		else //left
		{
                	flow->parent->left=flow->left;
                        flow->left->parent=flow->parent;
                        free(flow);
			return;
		}
	}

	// if left child is empty
	if (flow->left==NULL) // right
	{
		if (flow == flow->parent->right)
		{
			flow->parent->right=flow->right;
			flow->right->parent=flow->parent;
			free(flow);
			return;
		}
		else
		{
			flow->parent->left=flow->right;
			flow->right->parent=flow->parent;
			free(flow);
			return;
		}

	}

	// neither left nor right are empty!

	struct flow_list_bst_type *ptr = flow->right;

        while (ptr->left!=NULL)
        {
                ptr=ptr->left;
        }

	memcpy(&(flow->flow),&(ptr->flow),sizeof(struct flow_type));

	deleteFlowBST(ptr);
}
