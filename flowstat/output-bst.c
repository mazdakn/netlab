#include "flow.h"


// print detail of a single packet
void showPacketBST(struct flow_list_bst_head_type *flowList, struct packet_type *ptr)
{
	fprintf (flowList->procInfo.outputFile,"%ld ",flowList->procStat.allPacketCounter);
	fprintf (flowList->procInfo.outputFile,"%ld:%ld ",ptr->time_sec,ptr->time_usec);

	fprintf(flowList->procInfo.outputFile," %s",inet_ntoa(ptr->node1.info.ip));
        fprintf(flowList->procInfo.outputFile,":%hu",ptr->node1.info.port);

	fprintf(flowList->procInfo.outputFile," -> %s",inet_ntoa(ptr->node2.info.ip));
        fprintf(flowList->procInfo.outputFile,":%hu",ptr->node2.info.port);

	fprintf (flowList->procInfo.outputFile," Seq %u",ptr->info.seq);
        fprintf (flowList->procInfo.outputFile," Ack %u",ptr->info.ack);
	fprintf (flowList->procInfo.outputFile," Win %u",ptr->info.win);
	fprintf (flowList->procInfo.outputFile," Len %u",ptr->info.len);

	fprintf (flowList->procInfo.outputFile,"\n");

	fflush(flowList->procInfo.outputFile);
}

// print detail of a flow
void showFlowBST(struct flow_list_bst_head_type *flowList, struct flow_list_bst_type *ptr)
{
	fprintf (flowList->procInfo.outputFile,"%u ",flowList->procInfo.processId);
        fprintf (flowList->procInfo.outputFile,"%ld ",flowList->procStat.allPacketCounter);

	fprintf (flowList->procInfo.outputFile,"%ld:%ld ",ptr->flow.time_sec,ptr->flow.time_usec);

        fprintf(flowList->procInfo.outputFile," %s",inet_ntoa(ptr->flow.node1.info.ip));
        fprintf(flowList->procInfo.outputFile,":%hu",ptr->flow.node1.info.port);

        fprintf(flowList->procInfo.outputFile," <---> %s",inet_ntoa(ptr->flow.node2.info.ip));
        fprintf(flowList->procInfo.outputFile,":%hu",ptr->flow.node2.info.port);

        fprintf (flowList->procInfo.outputFile," Seq %u",ptr->flow.session1.seq);
        fprintf (flowList->procInfo.outputFile," Ack %u",ptr->flow.session1.ack);
        fprintf (flowList->procInfo.outputFile," Win %u",ptr->flow.session1.win);

        fprintf (flowList->procInfo.outputFile," Seq %u",ptr->flow.session2.seq);
        fprintf (flowList->procInfo.outputFile," Ack %u",ptr->flow.session2.ack);
        fprintf (flowList->procInfo.outputFile," Win %u",ptr->flow.session2.win);

        fprintf (flowList->procInfo.outputFile,"\n");

	fflush(flowList->procInfo.outputFile);
}

// print detail about a flow
void showResultBST(struct flow_list_bst_head_type *flowList)
{
      	double procExecTime=difftime(flowList->procInfo.finTime,flowList->procInfo.startTime);

        fprintf (stderr,"* P[%2u/%u-%u]..",flowList->procInfo.processId,flowList->procInfo.noOfProcess,flowList->procInfo.pid);
        fprintf (stderr,"(P:%lu/%lu  L:%2.2f%%) ",flowList->procStat.processPacketCounter,flowList->procStat.allPacketCounter,
		flowList->procStat.allPacketCounter==0?0:(float)flowList->procStat.processPacketCounter*100/flowList->procStat.allPacketCounter);
        fprintf (stderr,"(S:%lu ",flowList->procStat.synPacketCounter);
        fprintf (stderr,"A:%lu ",flowList->procStat.ackPacketCounter);
        fprintf (stderr,"F:%lu ",flowList->procStat.finPacketCounter);
        fprintf (stderr,"R:%ld) ",flowList->procStat.rstPacketCounter);

        fprintf (stderr,"(U-F:%lu ",flowList->procStat.uniDirFlowCounter);
        fprintf (stderr,"B-F:%lu ",flowList->procStat.biDirFlowCounter);
        fprintf (stderr,"S3-F:%lu ",flowList->procStat.handshakeStaleFlowCounter);
        fprintf (stderr,"S-F:%lu) ",flowList->procStat.staleFlowCounter);

        fprintf (stderr,"(M1:%lu ",flowList->procStat.check1ErrorCounter);
        fprintf (stderr,"M2:%lu ",flowList->procStat.winCheckErrorCounter);
        fprintf (stderr,"PC:%lu) ",flowList->procStat.rawPacketErrorCounter);

	fprintf (stderr,"(ET:%dm:%2ds)",((int)procExecTime)/60,((int)procExecTime)%60);

	fprintf (stderr,"\n");

	fflush(stderr);
}

// show final result
void showFinalResultBST(struct flow_list_bst_head_type *flowList)
{
        fprintf (stderr,"\n\n- NO. of Processes %u\n\n",flowList->procInfo.noOfProcess);
        fprintf (stderr,"- All Packets: %ld\n",flowList->procStat.allPacketCounter);
        fprintf (stderr,"- Processed Packets: %ld\n\n",flowList->procStat.processPacketCounter);
        fprintf (stderr,"- SYN Packets: %ld\n",flowList->procStat.synPacketCounter);
        fprintf (stderr,"- ACK Packets: %ld\n",flowList->procStat.ackPacketCounter);
        fprintf (stderr,"- FIN Packets: %ld\n",flowList->procStat.finPacketCounter);
        fprintf (stderr,"- RST Packets: %ld\n\n",flowList->procStat.rstPacketCounter);

        fprintf (stderr,"- Uni-directional Flows: %ld\n",flowList->procStat.uniDirFlowCounter);
        fprintf (stderr,"- Bi-directional Flows: %ld\n",flowList->procStat.biDirFlowCounter);
        fprintf (stderr,"- Stale Flows: %ld\n",flowList->procStat.staleFlowCounter);
        fprintf (stderr,"- Handshaking Stale Flows: %ld\n\n",flowList->procStat.handshakeStaleFlowCounter);

        fprintf (stderr,"- Metric 1 errors: %ld\n",flowList->procStat.check1ErrorCounter);
        fprintf (stderr,"- Metric 2 errors: %ld\n",flowList->procStat.winCheckErrorCounter);
        fprintf (stderr,"- Packet Check errors %ld\n",flowList->procStat.rawPacketErrorCounter);

        fflush(stderr);
}
