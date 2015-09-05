// mydns v1.08 2015 by GM
// changelog
// v1.08 double backup dns query with 200ms timeout and separate boot & conf file
// v1.07 backup dns query to 8.8.8.8 with 200ms timeout  
// v1.06 200ms timeout during dns query to avoid thread stale

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <locale.h>
#include <time.h>

#define BUFMSG 10000
#define NTHREAD 256
#define NIPCLASS 2048
#define LENLIST 128
#define NCOMMONBLACKLIST 4000000
#define MAXSTEPS 100
#define TIMEOUTUSEC 200000

#ifdef TEST
#define BOOTCONFIG "/mydnstest/mydns.boot"
#define FILECONFIG "/mydnstest/mydns.conf"
#else
#ifdef TESTGM
#define BOOTCONFIG "/mydnsGM/mydns.boot"
#define FILECONFIG "/mydnsGM/mydns.conf"
#else
#define BOOTCONFIG "/mydns/mydns.boot"
#define FILECONFIG "/mydns/mydns.conf"
#endif
#endif

#define FILECOMMONBLACKLIST "/mydns/commonblacklist"
#define IPTOT 1048576
#define IPCLASS  0b00001010001000000000000000000000 // 10.32.0.0
#define IPPROF   0b01111111011111110000000000000000 // 127.127.0.0
#define IPMASK12 0b11111111111100000000000000000000 // 255.240.0.0
#define IPMASK16 0b11111111111111110000000000000000 // 255.255.0.0

struct arg_pass {
	char *mesg;
	int lenmesg;
	struct sockaddr_in cliaddr;
};
struct ip_class {
	unsigned long ipv4;
	int cidr;
	char id[50];
	unsigned long totquery;
	unsigned long totfiltered;
	int bl;
	char **mywl;
	int nmywl;
	char **mybl;
	int nmybl;
};

pthread_t *tid;
int sockfd;
struct ip_class *myipclass=NULL;
int totipclass=0,listenport;
char **commonblacklist;
long totcommonblacklist=0;
char dnserver[20],bkp1dns[20],bkp2dns[20],ipv4splash[20],ipv6splash[40],mypassword[40];
time_t starttime;
char cstarttime[30];
unsigned long totmalformed,totoutscope;
unsigned long mymask[33];
unsigned long *myprofile;

// comparison functions
static int mystrcmp(const void *p1, const void *p2){
	return strcmp(*(char * const *)p1,*(char * const *)p2);
}
static int myipcmp(const void *p1, const void *p2){
	long ret;
	ret=((struct ip_class *)p1)->ipv4-((struct ip_class*)p2)->ipv4;
	if(ret==0)return 0;
	return (ret>0)?1:-1;
}

// Binary search with maximum steps for generic ordered search
int mysearch(char **myvector,long lenvector,char *mylook){
	long zinit,zend,zpos;
	int result,i;
	zinit=0;
	zend=lenvector-1;
	for(i=0;i<MAXSTEPS;i++){
		zpos=(zinit+zend)/2;
		result=mystrcmp(&myvector[zpos],&mylook);
		if(result==0)return 1;
		if(result<0)zinit=zpos+1;
		else zend=zpos-1;
		if(zinit>zend||zinit>=lenvector||zend<0)break;
	}
	return 0;
}

// Binary search with maximum steps for ipclass search
long myipsearch(unsigned long ip_tocheck){
	long zinit,zend,myclass;
	unsigned long ip_mask;
	int i;
	zinit=0;
	zend=totipclass-1;
	for(i=0;i<MAXSTEPS;i++){
		myclass=(zinit+zend)/2;
		ip_mask=mymask[myipclass[myclass].cidr];
		if((ip_tocheck&ip_mask)==myipclass[myclass].ipv4)break;
		if((ip_tocheck&ip_mask)>myipclass[myclass].ipv4)zinit=myclass+1;
		else zend=myclass-1;
		if(zinit>zend||zinit>=totipclass||zend<0)return -1;
	}
	return myclass;
}

// common black list file reading
void myloadcommonblacklist(){
	long i;
	char *auxbuf;
	FILE *fp;
	auxbuf=(char *)malloc(BUFMSG*sizeof(char));
	for(i=0;i<totcommonblacklist;i++)free(commonblacklist[i]);
	totcommonblacklist=0;
	fp=fopen(FILECOMMONBLACKLIST,"rt");
	for(totcommonblacklist=0;;){
		fscanf(fp,"%s",auxbuf);
		commonblacklist[totcommonblacklist]=(char *)malloc((strlen(auxbuf)+1)*sizeof(char));
		strcpy(commonblacklist[totcommonblacklist],auxbuf);
		if(feof(fp))break;
		totcommonblacklist++;
	}
	fclose(fp);
	qsort(commonblacklist,totcommonblacklist,sizeof(char *),mystrcmp);
	free(auxbuf);
}

// ip class files reading
void myconfig(){
	FILE *fp;
	char *auxbuf,*auxwl,*auxbl,*aux,*auxi;
	struct sockaddr_in netip;
	int i,j;
	
	auxbuf=(char *)malloc(BUFMSG*sizeof(char));
	auxwl=(char *)malloc(BUFMSG*sizeof(char));
	auxbl=(char *)malloc(BUFMSG*sizeof(char));
	
	// deallocation for new allocation
	if(myipclass==NULL){
		for(i=0;i<totipclass;i++){
			for(j=0;j<myipclass[i].nmywl;j++)free(myipclass[i].mywl[j]);
			free(myipclass[i].mywl);
			for(j=0;j<myipclass[i].nmybl;j++)free(myipclass[i].mybl[j]);
			free(myipclass[i].mybl);
		}
		free(myipclass);
	}
	
	myipclass=(struct ip_class *)malloc(NIPCLASS*sizeof(struct ip_class));
	fp=fopen(FILECONFIG,"rt");
	for(totipclass=0;;){
		fscanf(fp,"%s %u %s %u %s %s",auxbuf,&myipclass[totipclass].cidr,myipclass[totipclass].id,&myipclass[totipclass].bl,auxwl,auxbl);
		if(feof(fp))break;
		myipclass[totipclass].totquery=myipclass[totipclass].totfiltered=0;
		inet_pton(AF_INET,auxbuf,&(netip.sin_addr));
		myipclass[totipclass].ipv4=ntohl(netip.sin_addr.s_addr)&mymask[myipclass[totipclass].cidr];
		
		// white list, / separated, \ terminated
		myipclass[totipclass].mywl=(char **)malloc(LENLIST*sizeof(char *));
		myipclass[totipclass].nmywl=0;
		for(aux=auxi=auxwl;;){
			for(;*aux!='\\';aux++)if(*aux=='/')break;
			if(*aux=='\\')break;
			*aux='\0';
			myipclass[totipclass].mywl[myipclass[totipclass].nmywl]=(char *)malloc((strlen(auxi)+1)*sizeof(char));
			strcpy(myipclass[totipclass].mywl[myipclass[totipclass].nmywl],auxi);
			myipclass[totipclass].nmywl++;
			aux++;
			auxi=aux;
		}
		qsort(myipclass[totipclass].mywl,myipclass[totipclass].nmywl,sizeof(char *),mystrcmp);
		
		// black list, / separated, \ terminated
		myipclass[totipclass].mybl=(char **)malloc(LENLIST*sizeof(char *));
		myipclass[totipclass].nmybl=0;
		for(aux=auxi=auxbl;;){
			for(;*aux!='\\';aux++)if(*aux=='/')break;
			if(*aux=='\\')break;
			*aux='\0';
			myipclass[totipclass].mybl[myipclass[totipclass].nmybl]=(char *)malloc((strlen(auxi)+1)*sizeof(char));
			strcpy(myipclass[totipclass].mybl[myipclass[totipclass].nmybl],auxi);
			myipclass[totipclass].nmybl++;
			aux++;
			auxi=aux;
		}
		qsort(myipclass[totipclass].mybl,myipclass[totipclass].nmybl,sizeof(char *),mystrcmp);
		totipclass++;
	}
	fclose(fp);
	qsort(myipclass,totipclass,sizeof(struct ip_class),myipcmp);
	
	free(auxbuf);
	free(auxwl);
	free(auxbl);
}

// domain search with maximum deep to avoid loops for not termination
int domsearch(char **myvector,long lenvector,char *mydom){
	char *aux;
	int i;
	if(lenvector==0)return 0;
	i=0;
	aux=mydom;
	for(;;){
		if(mysearch(myvector,lenvector,aux)==1)return 1;
		for(;;){
			if(*aux=='\0' || i>=BUFMSG)return 0;
			if(*aux=='.' && i+1<BUFMSG){
				aux++;
				break;
			}
		}
		aux++;
		i++;
	}
}

void *manage(void *arg_void){
	struct arg_pass *myarg=(struct arg_pass *)arg_void;
	int sockreq,lenrecv,i,j,ml,lenaux,lenanswer,wlok,blok,cblok,mystop,ret;
	long myclass,mystatus;
	unsigned int query;
	unsigned long ipidx;
	unsigned long ipsrcaddr,ipprofaddr,ip_tocheck,ipclassaddr;
	struct sockaddr_in reqaddr,netip;
	struct sockaddr_in6 reqaddr6;
	char *recv,*auxbuf,*dominio,*aux1,*aux2,ipbuf[30];
	time_t curtime;
	struct tm *loctime;
	double myuptime;
	struct timeval tv;
	
	recv=(char *)malloc(BUFMSG*sizeof(char));
	auxbuf=(char *)malloc(BUFMSG*sizeof(char));
	dominio=(char *)malloc(BUFMSG*sizeof(char));
	
	// check query header
	mystop=0;
	// QR B2 b7
	if(!mystop && ((*(myarg->mesg+2))&0b10000000)!=0){mystop=1; totmalformed++; }
	// AA B2 b2
	if(!mystop && ((*(myarg->mesg+2))&0b00000100)!=0){mystop=1; totmalformed++; }
	// Z B3 b6
	if(!mystop && ((*(myarg->mesg+3))&0b01000000)!=0){mystop=1; totmalformed++; }
	// Rcode B3 b3-0
	if(!mystop && ((*(myarg->mesg+3))&0b00001111)!=0){mystop=1; totmalformed++; }
	// Total Answer B6 B7
	if(!mystop && (*(myarg->mesg+6))!=0){mystop=1; totmalformed++; }
	if(!mystop && (*(myarg->mesg+7))!=0){mystop=1; totmalformed++; }
	
	// define the ip to check to implement the profiled port
	if(!mystop){
		ip_tocheck=ntohl(myarg->cliaddr.sin_addr.s_addr);
		if((ip_tocheck&IPMASK12)==IPCLASS){
			ipidx=ip_tocheck-IPCLASS;
			if(myprofile[ipidx]!=0)ip_tocheck=myprofile[ipidx];
		}
	}
	
	// define the filter class
	if(!mystop){
		myclass=myipsearch(ip_tocheck);
		if(myclass==-1){mystop=1; totoutscope++; }
	}
	
	// domain name analisys
	if(!mystop){
		lenanswer=0;
		for(i=0,aux1=dominio,aux2=myarg->mesg+12;;){
			ml=(int)*aux2;
			if(ml==0)break;
			aux2++;
			i+=ml;
			if(i>=BUFMSG){mystop=1; totmalformed++; break;}
			for(j=0;j<ml;j++)*aux1++=tolower(*aux2++);
			i++;
			if(i>=BUFMSG){mystop=1; totmalformed++; break;}
			*aux1++='.';
			lenanswer+=ml+1;
		}
		if(i==0)*aux1='\0';
		else *(--aux1)='\0';
	}
	
	// request analisys
	if(!mystop){
		myipclass[myclass].totquery++;
		
		// query type
		query=*(aux2+2);
		lenanswer+=5;
		
		// command processing
		if(query==16 && strncmp(dominio,"cmd",3)==0){
			for(aux1=dominio;*aux1!='\0';aux1++)if(*aux1=='/')break;
			if(*aux1=='\0')sprintf(auxbuf,"request malfomed");
			else {
				for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
				if(*aux1=='\0')sprintf(auxbuf,"missed password");
				else {
					*aux1='\0';
					if(strcmp(aux2,mypassword)!=0)sprintf(auxbuf,"wrong password");
					else {
						for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
						if(*aux1=='\0')sprintf(auxbuf,"missed command");
						else {
							*aux1='\0';
							// reload configuration
							if(strcmp(aux2,"reload")==0){
								myconfig();
								sprintf(auxbuf,"configuration reloaded");
							}
							// reload common black list
							else if(strcmp(aux2,"recbl")==0){
								myloadcommonblacklist();
								sprintf(auxbuf,"common black list reloaded");
							}
							// insert
							else if(strcmp(aux2,"insert")==0){
								for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
								if(*aux1=='\0')sprintf(auxbuf,"missed source IP");
								else {
									*aux1='\0';
									// check ipsrc inside 10.32.0.0/12
									inet_pton(AF_INET,aux2,&(netip.sin_addr));
									ipsrcaddr=ntohl(netip.sin_addr.s_addr);
									if((ipsrcaddr&IPMASK12)!=IPCLASS)sprintf(auxbuf,"wrong source IP");
									else {
										ipidx=ipsrcaddr-IPCLASS;
										for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
										if(*aux1=='\0')sprintf(auxbuf,"missed profile IP");
										else {
											*aux1='\0';
											// check ipprof inside 127.127.0.0/16
											inet_pton(AF_INET,aux2,&(netip.sin_addr));
											ipprofaddr=ntohl(netip.sin_addr.s_addr);
											if((ipprofaddr&IPMASK16)!=IPPROF)sprintf(auxbuf,"wrong profile IP");
											else {
												myprofile[ipidx]=ipprofaddr;
												sprintf(auxbuf,"user profile inserted");
											}
										}
									}
								}
							}
							// delete
							else if(strcmp(aux2,"delete")==0){
								for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
								if(*aux1=='\0')sprintf(auxbuf,"missed source IP");
								else {
									*aux1='\0';
									// check ipsrc inside 10.32.0.0/12
									inet_pton(AF_INET,aux2,&(netip.sin_addr));
									ipsrcaddr=ntohl(netip.sin_addr.s_addr);
									if((ipsrcaddr&IPMASK12)!=IPCLASS)sprintf(auxbuf,"wrong source IP");
									else {
										ipidx=ipsrcaddr-IPCLASS;
										myprofile[ipidx]=0;
										sprintf(auxbuf,"user profile removed");
									}
								}
							}
							// class
							else if(strcmp(aux2,"class")==0){
								for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
								if(*aux1=='\0')sprintf(auxbuf,"missed source IP");
								else {
									*aux1='\0';
									// check ipsrc inside 10.32.0.0/12
									inet_pton(AF_INET,aux2,&(netip.sin_addr));
									ipsrcaddr=ntohl(netip.sin_addr.s_addr);
									if((ipsrcaddr&IPMASK12)!=IPCLASS)sprintf(auxbuf,"wrong source IP");
									else {
										ipidx=ipsrcaddr-IPCLASS;
										if(myprofile[ipidx]==0)sprintf(auxbuf,"user profile IP %s without class",aux2);
										else {
											ipclassaddr=htonl(myprofile[ipidx]);
											inet_ntop(AF_INET,&ipclassaddr,ipbuf,sizeof(ipbuf));
											sprintf(auxbuf,"user profile IP %s into class %s",aux2,ipbuf);
										}
									}
								}
							}
							// stat
							else if(strcmp(aux2,"stats")==0){
								for(aux2=++aux1;*aux1!='\0';aux1++)if(*aux1=='/')break;
								if(*aux1=='\0')sprintf(auxbuf,"missed IP");
								else {
									*aux1='\0';
									inet_pton(AF_INET,aux2,&(netip.sin_addr));
									ipsrcaddr=ntohl(netip.sin_addr.s_addr);
									mystatus=myipsearch(ipsrcaddr);
									if(mystatus==-1)sprintf(auxbuf,"IP not configured");
									else {
										curtime=time(NULL);
										myuptime=difftime(curtime,starttime);
										ipsrcaddr=htonl(myipclass[mystatus].ipv4);
										inet_ntop(AF_INET,&ipsrcaddr,ipbuf,sizeof(ipbuf));
										sprintf(auxbuf,"IPnet=%s/%d id=%s uptime=%.0lf totquery=%lu filtered=%lu",ipbuf,myipclass[mystatus].cidr,myipclass[mystatus].id,myuptime,myipclass[mystatus].totquery,myipclass[mystatus].totfiltered);
									}
								}
							}
							// status
							else if(strcmp(aux2,"status")==0){
								sprintf(auxbuf,"start=%s totmalformed=%lu totoutscope=%lu",cstarttime,totmalformed,totoutscope);
							}
							// unknown
							else sprintf(auxbuf,"command unknown");
						}
					}
				}
			}
			lenaux=strlen(auxbuf);
			lenrecv=12+lenanswer+13+lenaux;
			if(lenrecv<BUFMSG){
				recv[0]=*myarg->mesg; recv[1]=*(myarg->mesg+1); recv[2]=129; recv[3]=128; recv[4]=*(myarg->mesg+4); recv[5]=*(myarg->mesg+5); recv[6]=0; recv[7]=1; recv[8]=0; recv[9]=0; recv[10]=0; recv[11]=0;
				memcpy(recv+12,myarg->mesg+12,lenanswer);
				aux1=recv+12+lenanswer;
				aux1[0]=192; aux1[1]=12; aux1[2]=0; aux1[3]=16; aux1[4]=0; aux1[5]=1; aux1[6]=0; aux1[7]=0; aux1[8]=14; aux1[9]=16; aux1[10]=0; aux1[12]=lenaux; aux1[11]=aux1[12]+1;
				memcpy(aux1+13,auxbuf,lenaux);
			}
		}
 		
 		else  {
 			// user whitelist
 			wlok=0;
 			if((query==1||query==28) && domsearch(myipclass[myclass].mywl,myipclass[myclass].nmywl,dominio))wlok=1;
 			
 			// user blacklist
 			blok=0;
 			if(!wlok && (query==1||query==28) && domsearch(myipclass[myclass].mybl,myipclass[myclass].nmybl,dominio))blok=1;
 			
 			// common black list
 			cblok=0;
 			if(!wlok && !blok && (query==1||query==28) && myipclass[myclass].bl && domsearch(commonblacklist,totcommonblacklist,dominio))cblok=1;
 			
 			// set splash
 			if(cblok || blok){
 				myipclass[myclass].totfiltered++;
 				if(query==28)lenrecv=12+lenanswer+28;
 				else lenrecv=12+lenanswer+16;
 				if(lenrecv<BUFMSG){
 					recv[0]=*myarg->mesg; recv[1]=*(myarg->mesg+1); recv[2]=129; recv[3]=128; recv[4]=*(myarg->mesg+4); recv[5]=*(myarg->mesg+5); recv[6]=0; recv[7]=1; recv[8]=0; recv[9]=0; recv[10]=0; recv[11]=0; 
 					memcpy(recv+12,myarg->mesg+12,lenanswer);
 					aux1=recv+12+lenanswer;
 					if(query==28){
 						aux1[0]=192; aux1[1]=12; aux1[2]=0; aux1[3]=28; aux1[4]=0; aux1[5]=1; aux1[6]=0; aux1[7]=0; aux1[8]=14; aux1[9]=16; aux1[10]=0; aux1[11]=16;
 						inet_pton(AF_INET6,ipv6splash,&(reqaddr6.sin6_addr));
 						memcpy(aux1+12,&reqaddr6.sin6_addr.s6_addr,16);
 					}
 					else {
 						aux1[0]=192; aux1[1]=12; aux1[2]=0; aux1[3]=1; aux1[4]=0; aux1[5]=1; aux1[6]=0; aux1[7]=0; aux1[8]=14; aux1[9]=16; aux1[10]=0; aux1[11]=4;
 						inet_pton(AF_INET,ipv4splash,&(reqaddr.sin_addr));
 						memcpy(aux1+12,&reqaddr.sin_addr.s_addr,4);
 					}
 				}
 			}
 			
 			// resolution
 			else {
 				sockreq=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
 				tv.tv_sec=0;
 				tv.tv_usec=TIMEOUTUSEC;
 				setsockopt(sockreq,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
 				memset((char *)&reqaddr,0,sizeof(reqaddr));
 				reqaddr.sin_family=AF_INET;
 				reqaddr.sin_addr.s_addr=inet_addr(dnserver);
 				reqaddr.sin_port=htons(53);
 				sendto(sockreq,myarg->mesg,myarg->lenmesg,0,(struct sockaddr *)&reqaddr,sizeof(reqaddr));
 				lenrecv=recvfrom(sockreq,recv,BUFMSG,0,NULL,NULL);
 				close(sockreq);
 				if(lenrecv<1){
 					sockreq=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
 					tv.tv_sec=0;
 					tv.tv_usec=TIMEOUTUSEC;
 					setsockopt(sockreq,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
 					memset((char *)&reqaddr,0,sizeof(reqaddr));
 					reqaddr.sin_family=AF_INET;
 					reqaddr.sin_addr.s_addr=inet_addr(bkp1dns);
 					reqaddr.sin_port=htons(53);
 					sendto(sockreq,myarg->mesg,myarg->lenmesg,0,(struct sockaddr *)&reqaddr,sizeof(reqaddr));
 					lenrecv=recvfrom(sockreq,recv,BUFMSG,0,NULL,NULL);
 					close(sockreq);
 				}
 				if(lenrecv<1){
 					sockreq=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
 					tv.tv_sec=0;
 					tv.tv_usec=TIMEOUTUSEC;
 					setsockopt(sockreq,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));
 					memset((char *)&reqaddr,0,sizeof(reqaddr));
 					reqaddr.sin_family=AF_INET;
 					reqaddr.sin_addr.s_addr=inet_addr(bkp2dns);
 					reqaddr.sin_port=htons(53);
 					sendto(sockreq,myarg->mesg,myarg->lenmesg,0,(struct sockaddr *)&reqaddr,sizeof(reqaddr));
 					lenrecv=recvfrom(sockreq,recv,BUFMSG,0,NULL,NULL);
 					close(sockreq);
 				}
 			}
 		}
 		
 		// answer
 		sendto(sockfd,recv,lenrecv,0,(struct sockaddr *)&myarg->cliaddr,sizeof(myarg->cliaddr));
 	}
 	
 	free(recv);
  free(auxbuf);
  free(dominio);
  return NULL;
}

int main(int argc, char**argv){
	struct arg_pass *myargs;
	int lenmesg,i,j;
	struct sockaddr_in servaddr,cliaddr;
	socklen_t len;
	long pos;
	struct tm *loctime;
	FILE *fp;
	
	// initialization
	totmalformed=totoutscope=0;
	tid=(pthread_t *)malloc(NTHREAD*sizeof(pthread_t));
	commonblacklist=(char **)malloc(NCOMMONBLACKLIST*sizeof(char *));
	setlocale(LC_NUMERIC,"");
	starttime=time(NULL);
	loctime=localtime(&starttime);
	strftime(cstarttime,30,"%Y%m%dT%H%M%S",loctime);
	myargs=(struct arg_pass *)malloc(NTHREAD*sizeof(struct arg_pass));
	for(i=0;i<NTHREAD;i++)myargs[i].mesg=(char *)malloc(BUFMSG*sizeof(char));
	for(i=0;i<=32;i++)mymask[i]=~((1<<(32-i))-1);
	myprofile=(unsigned long *)malloc(IPTOT*sizeof(unsigned long));
	for(pos=0;pos<IPTOT;pos++)myprofile[pos]=0;
	
	// boot configuration file
	fp=fopen(BOOTCONFIG,"rt");
	fscanf(fp,"%d %s %s %s %s %s %s",&listenport,dnserver,bkp1dns,bkp2dns,mypassword,ipv4splash,ipv6splash);
	fclose(fp);
	
	// loading configuration file and common black list
	myconfig();
	myloadcommonblacklist();
	
	// bindind
	sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	memset((char *)&servaddr,0,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	servaddr.sin_addr.s_addr=htonl(INADDR_ANY);
	servaddr.sin_port=htons(listenport);
	bind(sockfd,(struct sockaddr *)&servaddr,sizeof(servaddr));
	len=sizeof(cliaddr);
	
	for(j=0;;){
		// receive request and launch a processing thread
		myargs[j].lenmesg=recvfrom(sockfd,myargs[j].mesg,BUFMSG,0,(struct sockaddr *)&myargs[j].cliaddr,&len);
		pthread_create(&(tid[j]),NULL,&manage,&myargs[j]);
		pthread_detach(tid[j]);
		if(++j==NTHREAD)j=0;
	}
}
