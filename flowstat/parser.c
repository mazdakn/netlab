#include "flow.h"

// this function is called by pcap_loop() for each pakcet
void PacketParser(u_char *user, const struct pcap_pkthdr *header,const u_char *payload)
{
	struct  ip *ip_ptr=NULL; //  a pointer to the beginning of IP header
	struct tcphdr *tcp_ptr=NULL; // pointer to the beginning of TCP header
	u_int8_t *tcp_option_ptr=NULL; // a pointer to the beinning of TCP options
	struct flow_list_bst_head_type *flowList=(struct flow_list_bst_head_type *)(user); // set DS passed by child process
	int ip_len=0; // IP header length
	int tcp_len=0; // TCP header length
	int tcp_option_len=0; // TCP options length
	int tcp_option_counter=0; // a counter of TCP option bytes
	int tcp_option_kind=0; // a variable holding type of a TCP option
	int tcp_option_kind_len=0; // a variable holding len of a TCP option

	struct flow_list_bst_type *flowPtr=NULL; // a pointer to the flow that this packet correspond
	struct packet_list_type *packetPtr=NULL; // a pointer to the packet information(Seq, Len) in the flowPtr linked list
	struct packet_type packet; // variable that holds all required decoded information of packet

	memset(&packet,0,sizeof(struct packet_type)); // packet initialization

        flowList->procStat.allPacketCounter++;

	// check if there is enough bytes in the captured data
        if (header->caplen < 2*TCP_NORMAL_HEADER_LEN+(flowList->procInfo.l2_len))
        {
		flowList->procStat.rawPacketErrorCounter++;
                return;
        }

	// this section is for packet decoding
	// every thing that is decoded should be converted to local machine architecure, using ntohs, ntohl..

	ip_ptr=(struct ip *)(payload+flowList->procInfo.l2_len); // pointer to begining of IP header
	ip_len=(ip_ptr->ip_hl)*4; // read length of IP header
	tcp_ptr=(struct tcphdr*)(payload+flowList->procInfo.l2_len+ip_len); // pointer to the beginning of TCP header 
	tcp_len=(tcp_ptr->doff)*4; // read length of TCP header

	tcp_option_ptr=(u_int8_t *)(payload+flowList->procInfo.l2_len+ip_len+TCP_NORMAL_HEADER_LEN); //pointer to the TCP options
	tcp_option_len=tcp_len-TCP_NORMAL_HEADER_LEN; // read TCP Options length

	packet.info.len=ntohs(ip_ptr->ip_len)-ip_len-tcp_len; // set length of data in the packet

	// set captured time of packet
	packet.time_sec=header->ts.tv_sec;
	packet.time_usec=header->ts.tv_usec;

	// decode source IP and TCP port
	packet.node1.hash=0;
	packet.node1.info.ip=ip_ptr->ip_src; // no ntohl reququired??!!!
	packet.node1.info.port=ntohs(tcp_ptr->source);

	// decode destination IP and TCP port
	packet.node2.hash=0;
	packet.node2.info.ip=ip_ptr->ip_dst; // no ntohl required?!!!
	packet.node2.info.port=ntohs(tcp_ptr->dest);

	// distribution algorithm
	// packets are distributed between processes based on sum of their hash1 and hash2
	// if mod of hash1+hash2 to no. of process is  equal to process ID then continue
	// otherwise return
	//
	// primarily hash1+hash2 was used for this part, but later we thought it's simpler and less complex to use port1+port2 
	if ((packet.node1.info.port+packet.node2.info.port) % flowList->procInfo.noOfProcess != flowList->procInfo.processId)
	{
		return;
	}

        flowList->procStat.processPacketCounter++; // increament no. of processed packets

	// decode TCP seq, ack, and windows fields
	packet.info.seq=ntohl(tcp_ptr->seq);
	packet.info.ack=ntohl(tcp_ptr->ack_seq);
	packet.info.win=ntohs(tcp_ptr->window);

	//showPacketBST(flowList,&packet);

	// decode TCP flags
	packet.state.value=NIL;
	packet.state.bits.syn=tcp_ptr->syn;
	packet.state.bits.ack=tcp_ptr->ack;
	packet.state.bits.rst=tcp_ptr->rst;
	packet.state.bits.fin=tcp_ptr->fin;

        if (packet.state.bits.syn==SET) flowList->procStat.synPacketCounter++;
        if (packet.state.bits.ack==SET) flowList->procStat.ackPacketCounter++;
        if (packet.state.bits.rst==SET) flowList->procStat.rstPacketCounter++;
        if (packet.state.bits.fin==SET) flowList->procStat.finPacketCounter++;

	// decode TCP options
	// read RFC to understang this part
	// but to say it short:
	// there are 2 type of TCP options:
	// 1 - TCP option type 1, which is NOP and TCP option type 0 which is end of TCP options. these 2 type are only 1 bytes
	// 2 - other type of TCP options has 3 fields, TYPE, LEN, Data and Len should be at least 2 Bytes
        //
	// for this program we needo only Windows Scaling options, which is set only in SYN packet
	// it's type is 3, and Data is 1 byte, which shows no. of shift to left for tcp windows
	if (packet.state.bits.syn==SET) // check if SYN is set
        {
                while (tcp_option_counter<tcp_option_len)
                {
                        tcp_option_kind=(*tcp_option_ptr++); // read TCP option type
                        tcp_option_counter++;

                        if (tcp_option_kind==0) break; //type 0 is end of TCP options
                        if (tcp_option_kind==1) continue; // type 1 is NOP

                        tcp_option_kind_len=(*tcp_option_ptr++); // if not type 0 or 1, read TCP option len
                        tcp_option_counter++;

                        if (tcp_option_kind_len<2) // TCP option len should be bigger than 2
                        {
				// if TCP option len is smaller than 2, and there is already a flow for this packet, delete the flow
                                struct flow_list_bst_type *flowPtrTmp;

                                if ((flowPtrTmp=searchFlowBST(flowList,&packet))!=NULL) // search to find if there is a flow for this packet
                                {
                                       	deleteFlowBST(flowPtrTmp); // delete the flow
                                }

                                return;
                        }

                        if ((tcp_option_kind==3) && (tcp_option_kind_len==3)) // if type is 3 and len is 3, it's a valid window scaling option
                        {
                                packet.info.tcp_wscaling=(*tcp_option_ptr); // read 1 byte of windows scaling
                                packet.info.tcp_wscaling_permitted=SET; // set windows scaling is permitted
                        }

			// got to the next TCP option
                        tcp_option_kind_len-=2;
                        tcp_option_counter+=tcp_option_kind_len;
                        tcp_option_ptr+=tcp_option_kind_len;
                }
        }

	// this part if for handling packet, and flows
	// check if packet is already a part of open flow
	// if not, create a new flow
	// otherwise update and check the existing flow
	if ((flowPtr=searchFlowBST(flowList,&packet))==NULL)
	{
		// if no related flow found and it's a SYN packet, insert a new flow in the DS
		if (packet.state.value==SYN)
		{
        	        flowPtr=insertFlowBST(flowList,&packet); // insert floww to DS

			flowPtr->flow.state.value=SYN; // set flow state as SYN

			// update flow time information
			flowPtr->flow.time_sec=packet.time_sec;
			flowPtr->flow.time_usec=packet.time_usec;

			// increase Uni directional flow counter

			flowList->procStat.uniDirFlowCounter++;

			// update flow information to expected ones
			flowPtr->flow.session1.expAck=packet.info.seq+1;
			flowPtr->flow.session1.maxSeq=packet.info.seq;
                        flowPtr->flow.session1.lastAck=NIL;

			// if wscalling is set, save it to flow
			if (packet.info.tcp_wscaling_permitted==SET)
			{
				flowPtr->flow.session2.tcp_wscaling=packet.info.tcp_wscaling;
				flowPtr->flow.session2.tcp_wscaling_permitted=SET;
			}

			return;
		}
	}
	else // if packet is part of open flow
	{
		// update flow time information
               	flowPtr->flow.time_sec=packet.time_sec;
               	flowPtr->flow.time_usec=packet.time_usec;

		// check direction of packet regarding the flow
		// if packet.hash1 == flow.hash1, it's a packet in direct path
		// if packet.hash1 == flow.hash2, it's a packet in reverse path
		if (packet.node1.hash==flowPtr->flow.node1.hash)
		{
			packet.state.bits.dir=UNSET;
		}
		else
		{
			packet.state.bits.dir=SET;
		}

		// decide based on the state of the flow
		switch (flowPtr->flow.state.value)
		{
			case SYN: // if SYN packet has been seen

				// if this is packet is a SYN/ACK and in reverse path
				// and packet ACK is equal to expACk, it's a correct SYN/ACK packet
				if ((packet.state.value==SYN+ACK+REV) && (packet.info.ack==flowPtr->flow.session1.expAck))
				{
					flowPtr->flow.state.value=SYN+ACK; // change flow state to SYN+ACK

					// update flow information
					// for metric 1
					flowPtr->flow.session2.expAck=packet.info.seq+1;
					flowPtr->flow.session2.maxSeq=packet.info.seq;
					flowPtr->flow.session2.seq=packet.info.seq;

					// for metric 2
					flowPtr->flow.session1.win=packet.info.win;
					flowPtr->flow.session1.ack=packet.info.ack;

					// check window scalling option
					// if win scalling is used, apply it
                                	if (packet.info.tcp_wscaling_permitted==SET)
       	                        	{
               	                        	flowPtr->flow.session1.tcp_wscaling=packet.info.tcp_wscaling;
						flowPtr->flow.session1.tcp_wscaling_permitted=SET;
                       	        	}

					return;
				}
				else // if it's not an expected SYN/ACK packet , delete the flow
				{
					deleteFlowBST(flowPtr);
					return;
				}
				break;
			case SYN+ACK: // if SYN/ACK in reverse path has been seen
				// if this is a ACK packet in direct path
				if ((packet.state.value==ACK) && (packet.info.ack==flowPtr->flow.session2.expAck))
				{

					flowPtr->flow.state.value=OPEN; // set this flow as passed the 3-way handshaking

					//showFlowBST(flowList,flowPtr);

					// update flow statistics
					flowList->procStat.uniDirFlowCounter--;
                	        	flowList->procStat.biDirFlowCounter++;

					// for metric 2
 					flowPtr->flow.session2.win=packet.info.win;
					flowPtr->flow.session2.ack=packet.info.ack;

					// for metric 1
					flowPtr->flow.session1.seq=packet.info.seq;
					flowPtr->flow.session1.expAck+=packet.info.len; /// for data in 3-way handshak

					// if Win scalling is set in this direction, apply it
                                     	if (flowPtr->flow.session2.tcp_wscaling_permitted==SET)
       	                                {
               	                        	flowPtr->flow.session2.win = (flowPtr->flow.session2.win << flowPtr->flow.session2.tcp_wscaling);
                       	                }

					// check metric 2
					// packet len+seq should be in boundry of window of other node
                               		if (packet.info.seq+packet.info.len > (flowPtr->flow.session1.ack+flowPtr->flow.session1.win))
                                       	{
                                       		fprintf (flowList->procInfo.outputFile,"[M2] ");
                                               	showFlowBST(flowList,flowPtr);
                                               	flowList->procStat.winCheckErrorCounter++;
                                               	deleteFlowBST(flowPtr);
                                               	return;
                               		}

                       			return;
				}
				else // if this is not a valid ACK ( as third part of 3 way handshak) delete it
				{
					deleteFlowBST(flowPtr);
					return;
				}
				break;

			// if packet belong to an open flow or half closed flow, go through this case
			case OPEN:
			case CLOSE1:
			case CLOSE2:
				if (packet.state.bits.ack == SET) // if FIN flag is set
				{
					if (packet.state.bits.dir == UNSET) // if packet is in direct path
					{

						// update flow info for this direction
                                               	flowPtr->flow.session1.seq=packet.info.seq;
                                               	flowPtr->flow.session2.win=packet.info.win;
                                               	flowPtr->flow.session2.ack=packet.info.ack;

						// apply windows scalling option
						if (flowPtr->flow.session2.tcp_wscaling_permitted==SET)
						{
							flowPtr->flow.session2.win = (flowPtr->flow.session2.win << flowPtr->flow.session2.tcp_wscaling);
						}

						// this part is for wrap around scenario, when 32 bit Seq field overflows
						if ((flowPtr->flow.session2.expAck > SEQ_LIMIT) && 
							((flowPtr->flow.session2.expAck % SEQ_MOD) >= packet.info.ack))
						{
                                               		flowPtr->flow.session2.expAck = flowPtr->flow.session2.expAck % SEQ_MOD;
						}

						// metric 1 algorithm
						if (packet.info.ack==flowPtr->flow.session2.expAck)
						{
							flowPtr->flow.session2.lastAck=packet.info.ack;
						}
						else if (packet.info.ack > flowPtr->flow.session2.expAck)
						{
							fprintf (flowList->procInfo.outputFile,"[M1] ");
							showFlowBST(flowList,flowPtr);
                                               		flowList->procStat.check1ErrorCounter++;
							deleteFlowBST(flowPtr);
							return;
						}

						if (packet.info.seq == flowPtr->flow.session1.lastAck)
						{
							if (packet.info.seq >= flowPtr->flow.session1.maxSeq)
							{
								deleteAllPackets(flowPtr->flow.session1.head);
								flowPtr->flow.session1.maxSeq=0;
							}

							flowPtr->flow.session1.lastAck=0;
						}

						if ((packetPtr=searchPacket(flowPtr->flow.session1.head, packet.info.seq))==NULL)
						{
							flowPtr->flow.session1.expAck+=packet.info.len;
							packetPtr=insertPacket(flowPtr->flow.session1.head, packet.info.seq, packet.info.len);

							if (packet.info.seq > flowPtr->flow.session1.maxSeq)
							{
								flowPtr->flow.session1.maxSeq = packet.info.seq;
							}
						}
						else if (packetPtr->len< packet.info.len)
						{
							flowPtr->flow.session1.expAck-=packetPtr->len;
							flowPtr->flow.session1.expAck+=packet.info.len;
							packetPtr->len=packet.info.len;
						}

						if (packet.state.bits.fin == SET)
						{
							flowPtr->flow.session1.expAck++;
							packetPtr->len=0;
						}


						// metric 2 algorithm
                                               	//if (flowPtr->flow.session1.expAck > (flowPtr->flow.session1.ack+flowPtr->flow.session1.win))
                                               	if (packet.info.seq+packet.info.len > (flowPtr->flow.session1.ack+flowPtr->flow.session1.win))
                                               	{
                                        		fprintf (flowList->procInfo.outputFile,"[M2] ");
                                                       	showFlowBST(flowList,flowPtr);
							flowList->procStat.winCheckErrorCounter++;
                                                       	deleteFlowBST(flowPtr);
                                                       	return;
                                               	}
					}
					else // if packet belogns to reverse path of flow
					{
						// update flow information in this direction
                                               	flowPtr->flow.session2.seq=packet.info.seq;
                                                flowPtr->flow.session1.win=packet.info.win;
       	                                        flowPtr->flow.session1.ack=packet.info.ack;

						// apply windows scalling information
                                               	if (flowPtr->flow.session1.tcp_wscaling_permitted==SET)
       	                                        {
               	                                       	flowPtr->flow.session1.win = (flowPtr->flow.session1.win << 
								flowPtr->flow.session1.tcp_wscaling);
                                                }

						// wrap around scenario
       	                                        if ((flowPtr->flow.session1.expAck > SEQ_LIMIT) && 
               	                                        ((flowPtr->flow.session1.expAck % SEQ_MOD) >= packet.info.ack))
                       	                       	{
                               	                        flowPtr->flow.session1.expAck = flowPtr->flow.session1.expAck % SEQ_MOD;
                                       	       	}

						// metric 1 algotihm
                                               	if (packet.info.ack==flowPtr->flow.session1.expAck)
                                               	{
                                                       	flowPtr->flow.session1.lastAck=packet.info.ack;
                                               	}
                                                else if (packet.info.ack > flowPtr->flow.session1.expAck)
       	                                        {
               	                                        fprintf (flowList->procInfo.outputFile,"[M1] ");
                       	                                showFlowBST(flowList,flowPtr);
                        	                        flowList->procStat.check1ErrorCounter++;
                                       	                deleteFlowBST(flowPtr);
                                               	        return;
                                       		}

                                                if (packet.info.seq == flowPtr->flow.session2.lastAck)
       	                                        {
               	                                        if (packet.info.seq >= flowPtr->flow.session2.maxSeq)
                       	                                {
                               	                                deleteAllPackets(flowPtr->flow.session2.head);
                                       	                        flowPtr->flow.session2.maxSeq=0;
                                               	        }

                                                       	flowPtr->flow.session2.lastAck=0;
                                               	}

                                                if ((packetPtr=searchPacket(flowPtr->flow.session2.head, packet.info.seq))==NULL)
	                                        {
               	                                        flowPtr->flow.session2.expAck+=packet.info.len;

                       	                                packetPtr=insertPacket(flowPtr->flow.session2.head, packet.info.seq, packet.info.len);

                               	                        if (packet.info.seq > flowPtr->flow.session2.maxSeq)
                                       	                {
                                               	                flowPtr->flow.session2.maxSeq = packet.info.seq;
                                                       	}
                                               	}
                                                else if (packetPtr->len< packet.info.len)
       	                                        {
               	                                        flowPtr->flow.session2.expAck-=packetPtr->len;
                       	                                flowPtr->flow.session2.expAck+=packet.info.len;
                               	                        packetPtr->len=packet.info.len;
                                       	        }

                                               	if (packet.state.bits.fin == SET)
                                               	{
                                                       	flowPtr->flow.session2.expAck++;
                                                        packetPtr->len=0;
       	                                        }

						// metric 2 algorithm
               	                                //if (flowPtr->flow.session2.expAck > (flowPtr->flow.session2.ack+flowPtr->flow.session2.win))
                       	                        if (packet.info.seq+packet.info.len > (flowPtr->flow.session2.ack+flowPtr->flow.session2.win))
						{
                                       	          	fprintf (flowList->procInfo.outputFile,"[M2] ");
                                               	        showFlowBST(flowList,flowPtr);
							flowList->procStat.winCheckErrorCounter++;
                                                        deleteFlowBST(flowPtr);
       	                                                return;
               	                                }
					}
				}

				// if packet is a FIN, close flow in that direction
	                	if (packet.state.bits.fin==SET)
                		{
					// check FIN packet is for which direction
					if (packet.state.bits.dir == UNSET)
					{
                       				flowPtr->flow.state.bits.bit7=UNSET;
					}
					else
					{
						flowPtr->flow.state.bits.bit6=UNSET;
					}

					// if flow is closed in both directions, delete it
					if (flowPtr->flow.state.value < CLOSE)
					{
						deleteFlowBST(flowPtr);
                       				return;
					}
               			}

				// if packet is RST, delete flow, no matter which on which direction is it
				if (packet.state.bits.rst==SET)
				{
					deleteFlowBST(flowPtr);
					return;
				}
				break;
			default: // this situation should never happen
				fprintf (stderr,"report unkown condition\n");
				break;
       		}
	}
}
