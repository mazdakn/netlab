/*
 * Copyright (C) 2011 Mazdak Rajabi Nasab
 * 
 * flowstat is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * flowstat is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.

 * Mazdak Rajabi Nasab, mazdak@student.chalmers.se
 * Behrooz Sangchooloe, behsan@student.chalmers.se

 * This program uses libpcap library to read and access captured traces in pcap format.
*/



#include "main.h"

int main(int argc,char *argv[])
{
	char errbuffer[PCAP_ERRBUF_SIZE]; //error buffer for libpcap function calls, as mentioned in the libpcap documentation
	char *device=NULL; // variable for name of the input, file name of captured file, or an interface name
	pcap_t *dev_handler=NULL; // opened handler for libpcap functions
	struct bpf_program filter; //a structure for compiling pcap filter and then applying to trace
	int return_code; // return code of pcap_loop()
	int procNo=0; // No of processes
	int i; // temporary variable
	FILE * outputFile; // outut file for each process
	time_t progStartTime; // time varibale to hold start time of program
	time_t progFinTime; // time varibale to hold end of program execution

	// chech if enough argument is passed to the program
	// usage: ./flowstat [dev|file] [device name|file name] [number of process] [output file]
	if (argc != 5)
	{
		fprintf (stderr,"Usage: %s [dev|file] [device|filename] [No. of Process] [output]\n",argv[0]);
		exit(EXIT_FAILURE);
	}

	// read no. of process
	// check to verify if it's possible
        procNo=atoi(argv[3]);

	// check no. of process. it should be bigger than 0, but the max number can be anything. however, more process means more process switching, 
	// which decreases program performance and increases program execution time.
	if ((procNo>MAX_NO_PROCCESS) || (procNo<1))
        {
                fprintf (stderr,"invalid number of process. ( 0 < no. of proccess < %d)\n",MAX_NO_PROCCESS);
                exit(EXIT_FAILURE);
        }

	fprintf (stderr,"- input: %s\n",argv[2]); // argv[2] is input name, it should be checked for correctness
	fprintf (stderr,"- output: %s\n",argv[4]); //argv[3] is output file

	// print and save start of program execution time
	progStartTime=time(NULL);
	fprintf (stderr,"- Starting time: %s",ctime((const time_t *)&progStartTime));

	fprintf (stderr,"- processes: %d\n\n",procNo); //print no. of process

	int procResultPipe[2]; // pipe for IPC between main process and childs, which is for sending result from child process to main process

	// creatine pipe, as mentioned for IPC, main process reads this pipe and child process write their result into this pipe
	if (pipe(procResultPipe)!=0)
	{
		perror(" Pipe:");
		exit(EXIT_FAILURE);
	}

	// this loop is for creating porcesses
	for (i=0;i<procNo;i++)
	{
		pid_t pid=fork(); //create child process

		if (pid==-1) //pid==-1, shows an error
		{
			fprintf (stderr,"error in creating process\n");
			exit(EXIT_FAILURE);
		}

		if (pid>0) //parent proccess
		{
			// just save the start of child process life time and then goto the begining of loop
        		time_t timeTmp=time(NULL);
			fprintf (stderr,"* process [%2d/%d - %d]..started - %s",i,procNo,pid,ctime((const time_t *)&timeTmp));
			continue;
		}

		if (pid==0) // child process
		{

			close(procResultPipe[0]); //close the output of pipe, as childs are only writer for this pipe

			struct flow_list_bst_head_type *flowList; // data structure that child process use to hold informations

	                if ((flowList=malloc(sizeof(struct flow_list_bst_head_type)))==NULL) // memory allocation for data structure
                        {
                                fprintf (stderr,"can not assign memory to Head");
                                exit(EXIT_FAILURE);
                        }

			memset(flowList,0,sizeof(struct flow_list_bst_head_type)); //data structure initialization

	                if ((flowList->head=malloc(sizeof(struct flow_list_bst_type)))==NULL) // DS head allocation
                        {
                                fprintf(stderr,"can not assign memory to Head");
                                exit(EXIT_FAILURE);
                        }

			memset(flowList->head,0,sizeof(struct flow_list_bst_type)); // DS head initialization

                       	flowList->head->left=NULL;
                       	flowList->head->right=NULL;
			flowList->head->parent=NULL;

			// a good hash should be selected for hash1 and hash2, so DS would be balanced
			// search is primarily based on hash2 and then hash1, so hash1 can be set to 0
			// and hash2 to a medium value
		       	struct in_addr tmpAddr;
       			if (inet_aton("0.0.0.1",&tmpAddr)==0) //this can be 0!!!
			{
				fprintf (stderr,"what is wrong here\n");
				exit(EXIT_FAILURE);
			}

			// setting hash1 for head
			flowList->head->flow.node1.hash=0;
			flowList->head->flow.node1.info.ip=tmpAddr; //2^31, 127.0.0.0:0
			flowList->head->flow.node1.info.port=0;

                        if (inet_aton("0.0.0.1",&tmpAddr)==0)
                        {
                                fprintf (stderr,"what is wrong here\n");
                                exit(EXIT_FAILURE);
                        }

			// setting hash2 for head
                       	flowList->head->flow.node2.hash=0;
                       	flowList->head->flow.node2.info.ip=tmpAddr; // 2^31, 127.0.0.0:0
                       	flowList->head->flow.node2.info.port=0;

                        flowList->procInfo.processId=i;
                        flowList->procInfo.noOfProcess=procNo;

			// preparing the output, if argv[4] is stdout, then print to screen , otherwise print to a file
			// filename = argv[4]+"-"+process No.
                        if (strcmp(argv[4],"stdout")!=0)
                        {
                                char filename[200]; //it's better to be dynamic!!!

                                sprintf (filename,"%s-%d",argv[4],i);

                                if ((outputFile=fopen(filename,"w"))==NULL)
                                {
                                        perror ("file access:");
                                        exit(EXIT_FAILURE);
                                }
                        }
                        else
                        {
                                outputFile=stdout;
                        }

			// set output pipe and output file for process
			flowList->procInfo.outputFile=outputFile;
			flowList->procInfo.outputPipe=procResultPipe[1];

			// input to process is argv[2]
                        if ((flowList->procInfo.deviceName=malloc(strlen(argv[2])+1))==NULL)
                        {
                                fprintf(stderr,"Can not assign enough memory\n");
                                exit(EXIT_FAILURE);
                        }

                        strcpy(flowList->procInfo.deviceName,argv[2]);

			// check if input is file or a device
			if (strcmp(argv[1],"file")==0)
			{
				// if it's a file, open is it with pcap_open_offline()
			        if ((dev_handler=pcap_open_offline(flowList->procInfo.deviceName,errbuffer))==NULL)
        			{
                			fprintf(stderr,"Couldn't open file: %s\n",pcap_geterr(dev_handler));
                			exit(EXIT_FAILURE);
        			}
			}
			else if (strcmp(argv[1],"dev")==0)
			{
				// otherwise open it with pcap_open_live()
				// arguments:  capture 120 bytes, put it in promiscuous mode, no time out
				if ((dev_handler=pcap_open_live(device,120,1,0,errbuffer))==NULL)
                        	{
                                	fprintf(stderr,"Couldn't open file: %s\n",pcap_geterr(dev_handler));
                                	exit(EXIT_FAILURE);
                        	}
			}
			else
			{
				// if non, it's unkown command
				fprintf (stderr,"Unkown command\n");
				exit(EXIT_FAILURE);
			}

			// compile pcap filter
			if (pcap_compile(dev_handler,&filter,"tcp && ip",1,0) != 0)
       			{
        			fprintf(stderr,"Couldn't parse filter: %s\n",pcap_geterr(dev_handler));
                		exit(EXIT_FAILURE);
       			}

			// set pcap filter
        		if (pcap_setfilter(dev_handler,&filter)==-1)
        		{
        			fprintf(stderr,"Couldn't install filter: %s\n",pcap_geterr(dev_handler));
                		exit(EXIT_FAILURE);
     			}

			//save process start time
			flowList->procInfo.startTime=time(NULL);

			switch (pcap_datalink(dev_handler)) //check for L2 encapsulation
			{
				case DLT_EN10MB: // Ethernet
					flowList->procInfo.l2_len=sizeof(struct ether_header); // set L2 header size
					// run process and pass to it input and a pointer to DS
					return_code = pcap_loop(dev_handler,-1,PacketParser,(u_char *)(flowList));
					break;
				case DLT_C_HDLC: //Cisco HDLC
					flowList->procInfo.l2_len=sizeof(struct chdlc_header); // set L2 Header size
					// run process and pass to it input and a pointer to DS
					return_code = pcap_loop(dev_handler,-1,PacketParser,(u_char *)(flowList));
                       			break;
				case DLT_LINUX_SLL: // Linux "cooked" capture encapsulation
                                        flowList->procInfo.l2_len=16; // set L2 Header size
                                        // run process and pass to it input and a pointer to DS
                                        return_code = pcap_loop(dev_handler,-1,PacketParser,(u_char *)(flowList));
					break;
				default: // other types
					fprintf (stderr,"[*] Unkown Data Link type %d\n",pcap_datalink(dev_handler));
					break;
			}

			flowList->procInfo.finTime=time(NULL); // save finishin time of process

			// free resouces
			free(device);
			pcap_close(dev_handler);

			// write result to the output pipe
			if (write(flowList->procInfo.outputPipe,flowList,sizeof(struct flow_list_bst_head_type))!=
				sizeof(struct flow_list_bst_head_type))
			{
				perror("write");
				exit(EXIT_FAILURE);
			}

			// exit and kill process
			exit(EXIT_SUCCESS);
		}
	}

	// this section is only for main process

	printf ("\n");

	// close pipe writer side, since main process is only reader
	close(procResultPipe[1]);

	// it's better to chang these varibles to only required parts! procStat part
	struct flow_list_bst_head_type flowListResult; // DS for reading from child process
	struct flow_list_bst_head_type flowListFinalResult; // DS for keeping all processes results

	// initializing DS with 0
	memset(&flowListFinalResult,0,sizeof(struct flow_list_bst_head_type));
	memset(&flowListResult,0,sizeof(struct flow_list_bst_head_type));

	// wait for all processe and read corresponding results
	for (i=0;i<procNo;i++)
	{
		int exitCode=0; // exit code for child, whether finished normally or not
		pid_t childPid=0; // child pid

		childPid=wait(&exitCode); // wait until child terminates
		//it's better to check the exit code of childs

		// read child results from the pipe
                if (read(procResultPipe[0],&flowListResult,sizeof(struct flow_list_bst_head_type))!=sizeof(struct flow_list_bst_head_type))
                {
                        perror("read");
                        exit(EXIT_FAILURE);
                }

		// show results of the child
		showResultBST(&flowListResult);

		// calculate the overall results
		flowListFinalResult.procStat.biDirFlowCounter+=flowListResult.procStat.biDirFlowCounter;
		flowListFinalResult.procStat.uniDirFlowCounter+=flowListResult.procStat.uniDirFlowCounter;
		flowListFinalResult.procStat.staleFlowCounter+=flowListResult.procStat.staleFlowCounter;
		flowListFinalResult.procStat.handshakeStaleFlowCounter+=flowListResult.procStat.handshakeStaleFlowCounter;

		flowListFinalResult.procStat.allPacketCounter=flowListResult.procStat.allPacketCounter;
		flowListFinalResult.procStat.processPacketCounter+=flowListResult.procStat.processPacketCounter;

		flowListFinalResult.procStat.synPacketCounter+=flowListResult.procStat.synPacketCounter;
		flowListFinalResult.procStat.ackPacketCounter+=flowListResult.procStat.ackPacketCounter;
		flowListFinalResult.procStat.finPacketCounter+=flowListResult.procStat.finPacketCounter;
		flowListFinalResult.procStat.rstPacketCounter+=flowListResult.procStat.rstPacketCounter;

		flowListFinalResult.procStat.check1ErrorCounter+=flowListResult.procStat.check1ErrorCounter;
		flowListFinalResult.procStat.winCheckErrorCounter+=flowListResult.procStat.winCheckErrorCounter;

		flowListFinalResult.procStat.rawPacketErrorCounter=flowListResult.procStat.rawPacketErrorCounter;

		flowListFinalResult.procInfo.noOfProcess=flowListResult.procInfo.noOfProcess;
	}

	printf ("\n");

	// save program finishing time
	progFinTime=time(NULL);

	// show final overall result
	showFinalResultBST(&flowListFinalResult);

	// printf info of program execution time
       	fprintf (stderr,"\n- program finishing time: %s",ctime((const time_t *)&progFinTime));
       	double execTime=difftime(progFinTime,progStartTime);
	fprintf (stderr,"- program execution time: %d min %2d sec\n\n",execTime==0?0:((int)execTime)/60,execTime==0?0:((int) execTime)%60);

	// it's better to have a cleaning part, like mempry cleaning and ...

	exit(EXIT_SUCCESS); // exit normally
}
