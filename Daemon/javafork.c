#define _GNU_SOURCE

/*
 * Be aware: this program uses GNU extensions (the TEMP_FAILURE_RETRY macro)
 * I am writing (non-)portable code because I am running out of time
 * TODO: my portable macro with the same funcionality
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <endian.h>
#include <time.h>
#include "javafork.h"



pid_t daemonPID;                /*Stores the daemon server PID*/
struct sigaction sigintAction;  /*Stores the init SIGINT sigaction value*/
int sockfd = -1;                /*Stores the daemon server TCP socket.*/







int main (int argc, char *argv[]) 
{
	int c;                      /*Getopt parameter*/
	/*Default values*/
	char *avalue = IPADDRESS;   /*Address: numeric value or hostname*/
	int pvalue = PORT;          /*TCP port*/
	int qvalue = QUEUE;         /*TCP listen queue*/
    struct sigaction sa;        /*sig actions values*/

    /*This process is intended to be used as a daemon, it sould be launched by the INIT process, because of that*/
	/*we are not forking it (INIT needs it)*/
    /*TODO: I think this is not needed because setsid function performs it*/
	if (daemonize(argv[0], LOG_SYSLOG, LOG_PID) < 0)
		return -1;

	/*Changing session.*/	
    setsid();

	
	opterr = 0;
	while ((c = getopt (argc, argv, "a:p:q:")) != -1) {
		switch (c) {
		case 'a':
			avalue = optarg;
			break;
		case 'p':
			pvalue = atoi(optarg);
			if ((pvalue > 65535) || (pvalue <= 0)) {
				syslog (LOG_ERR, "Port value %d out of range", pvalue);
				return -1;
			}
			break;
		case 'q':
			qvalue = atoi(optarg);
			break;
		case '?':
			if ((optopt == 'a') || (optopt == 'p') || (optopt == 'q'))
				syslog (LOG_ERR, "Option -%c requires an argument.", optopt);
			else if (isprint (optopt))
				syslog (LOG_ERR, "Invalid option '-%c'.", optopt);
			else
				syslog (LOG_ERR, "Unknown option character '\\x%x'.", optopt);
			return -1;
		default:
			abort ();
		}
	}

	/*This program does not admit options*/
	if (optind < argc) {
		syslog (LOG_ERR,"This program does not admit options just argument elements with their values.");
		return -1;
	}
	

    daemonPID = getpid();
    /* If running from console, user may finish this process using SIGINT (Ctrl-C)*/
    /* Check to make sure that the shell has not set up an initial action of SIG_IGN before I establish my own signal handler.
     * As seen on http://www.gnu.org/software/libc/manual/html_node/Initial-Signal-Actions.html#Initial-Signal-Actions
     */
    memset (&sa, 0, sizeof(sa));
    memset (&sigintAction, 0, sizeof(sigaction));
    if (sigaction (SIGINT, NULL, &sa) < 0) {
        syslog (LOG_ERR, "SIGINT retrieve current signal handler failed: %m");
        return -1;
    }

    if (sa.sa_handler != SIG_IGN) {
        /* Save the current SIGINT sigaction value. We use it to restore SIGINT handler in my custom SIGINT handler.*/
        memcpy (&sigintAction, &sa, sizeof(sigaction));

        sa.sa_handler = &sigint_handler;
        sa.sa_flags = SA_RESTART;
        if (sigemptyset(&sa.sa_mask) < 0) {
            syslog (LOG_ERR, "SIGINT empty mask: %m");
            return -1;
        }
        if (sigaction(SIGINT, &sa, NULL) < 0) {
            syslog (LOG_ERR, "SIGINT set signal handler failed: %m");
            return -1;
        }
    }

	
	if (main_daemon (avalue, pvalue, qvalue) < 0)
		return -1;
	
	return 0;
}



int main_daemon (char *address, int port, int queue)
{
	struct protoent *protocol;          /*Network protocol*/
	struct sockaddr_in addr_server;	    /*struct with the server socket address*/
	struct sockaddr_in  addr_client;    /*struct with the client socket address*/
	int sockclient = -1;                /*File descriptor for the accepted socket*/
	pthread_t idThread;                 /*Thread identifier number*/
	socklen_t clilen;
	int optval;
	int returnValue = 0;                /*The return value from this function, OK by default*/
    sigset_t blockMask;
	
	
	/*Retrieve protocol number from /etc/protocols file */
	protocol=getprotobyname("tcp");
	if (protocol == NULL) {
		syslog(LOG_ERR, "cannot map \"tcp\" to protocol number: %m");
		goto err;
	}
	
    memset((char*) &addr_server, 0, sizeof(addr_server));
	addr_server.sin_family = AF_INET;
	if (inet_pton(AF_INET, address, &addr_server.sin_addr.s_addr) <= 0) {
		syslog (LOG_ERR, "error inet_pton: %m");
		goto err;
	}
	
	addr_server.sin_port = htons(port);
	
	if ((sockfd = socket(AF_INET, SOCK_STREAM, protocol->p_proto)) < 0) {
		syslog (LOG_ERR, "socket creation failed: %m");
		goto err; 
	}


	/*We want to avoid issues while trying to bind a socket in TIME_WAIT state*/
	optval = 1;
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
		syslog (LOG_ERR, "setsockopt failed: %m");
		goto err;
	}
	
	if (bind(sockfd, (struct sockaddr *) &addr_server, sizeof(addr_server)) < 0) {
		syslog (LOG_ERR, "socket bind failed: %m");
		goto err;
	}
	
	if (listen (sockfd, queue) < 0 ) {
		syslog (LOG_ERR, "socket listen failed: %m");
		goto err;
	}	
	
    /* Block SIGCHLD to prevent its delivery if a child terminates before the parent commences to wait for its end.*/
    /* This is a multithreaded application so, we must use pthread_sigmask. Besides from these references:
     * http://sunnyeves.blogspot.com.es/2010/09/sneak-peek-into-linux-kernel-chapter-2.html
     * http://en.wikipedia.org/wiki/Parent_process
     * The SIGCHLD signal is received by the parent process not the real parent (the real parent in this application is
     * the thread that we are going to launch right now) So, I must block the signal before launching threads, in this way
     * I am blocking the signal for the parent (this process) and the real one (the thread that is going to launch the command
     * sent by the user using a child process for that task) because from man pthread_sigmask "other threads created by main() will inherit
     * a copy of the signal mask". I wonder what could happen in case of using siprocmask.
     */
    if (sigemptyset(&blockMask) < 0) {
    syslog (LOG_ERR, "SIGCHLD empty mask: %m");
        goto err;
    }
    if (sigaddset(&blockMask, SIGCHLD) <0) {
    syslog (LOG_ERR, "SIGCHLD sigaddset mask: %m");
        goto err;
    }
    if (pthread_sigmask(SIG_BLOCK, &blockMask, NULL) == -1) {
    syslog (LOG_ERR, "pthread_sigmask failed: %m");
        goto err;
    }

    for(;;) {
		clilen =  sizeof(addr_client);
		if ((sockclient = TEMP_FAILURE_RETRY(accept (sockfd, (struct sockaddr *) &addr_client, &clilen))) < 0) {
			syslog (LOG_ERR, "socket accept failed: %m");
			goto err;
		}

		if (pthread_create (&idThread, NULL, serverThread, (void *)sockclient) != 0 ) {
			syslog (LOG_ERR, "thread creation failed: %m");
		}
	}

end:
    close (sockfd);
    return returnValue;
err:
	/*When there is an error.*/
	returnValue = -1;	
	goto end;
}



int daemonize(const char *pname, int facility, int option)
{
	int fd = -1;    /*Temporaly store for the /dev/tty and /dev/null file descriptors*/
	
	if ((fd = TEMP_FAILURE_RETRY(open( "/dev/tty", O_RDWR, 0))) == -1) {
        /*We already have no tty control*/
        close(fd);
        return 0;
	}

    /*TODO: Errors from syslog function*/
	/*Sending messages to log*/
	openlog(pname, option, facility);

	/*To get a controlling tty*/
	if (ioctl(fd, TIOCNOTTY, (caddr_t)0) <0 ) {
		syslog (LOG_ERR, "Getting tty failed: %m");
		return -1;
	}

	if (close(fd) < 0) {
		syslog (LOG_ERR, "Closing tty failed: %m");
		return -1;
	}
	
	if ((fd = TEMP_FAILURE_RETRY(open( "/dev/null", O_RDWR, 0))) == -1) {
		close(fd);
		return -1;
	}

	if (TEMP_FAILURE_RETRY(dup2(fd,0)) < 0 || 
        TEMP_FAILURE_RETRY(dup2(fd,1)) < 0 ||
        TEMP_FAILURE_RETRY(dup2(fd,2)) < 0) {
	    close(fd);
        return -1;
    }

    close(fd);

    return 0;
}



void *serverThread (void * arg)
{
    int socket = -1;                        /*Open socket by the Java client*/
    long timeout, utimeout;                 /*Timeout for reading data from client: secs and usecs*/
                                            /*respectively*/
    uint32_t commandLength = 0;             /*Store the command length*/
    unsigned char *command = NULL;          /*The command sent by the client as bytes, to be executed by this process*/
    unsigned char buffer[sizeof(unsigned char)]; /*This buffer is intended to store the data received from the client*/
	
	socket = (int) arg;
	
	pthread_detach(pthread_self());


    if (required_sock_options (socket) < 0)
        goto err;
	
	
            /****************************************************************************************/
            /*   Just over 1 TCP connection                                                         */
            /*   COMMAND_LENGTH: Java integer 4 bytes, BIG-ENDIAN (the same as network order)       */
            /*   COMMAND: locale character set encoding                                             */
            /*   RESULTS: locale character set encoding                                             */
            /*                                                                                      */
            /*          JAVA CLIENT: ------------ COMMAND_LENGTH -------> :SERVER                   */
            /*          JAVA CLIENT: -------------- COMMAND ------------> :SERVER                   */
            /*          JAVA CLIENT: <-------------- RESULTS ------------ :SERVER                   */
            /*          JAVA CLIENT: ----------- CLOSE CONNECTION ------> :SERVER                   */
            /*                                                                                      */
            /****************************************************************************************/

    /*Wait max 2 seconds for data coming from client, otherwise exits with error.*/
    timeout = 2;
    utimeout = 0;


    /*1. COMMAND LENGTH*/
    /*First of all we receive the command size as a Java integer (4 bytes primitive type)*/
    memset(buffer, 0, sizeof(buffer));

    if (receive_from_socket (socket, buffer, sizeof(uint32_t), timeout, utimeout) < 0)
        goto err;

    /*Retrieve integer (4 bytes) from buffer*/
    memcpy (&commandLength, buffer, sizeof(uint32_t));
    /*Java sends the primitive integer using big-endian order (it is the same as network order)*/
    commandLength = be32toh (commandLength);


    /*2. COMMAND*/
    /*Reserving commandLength + 1 because of the string end character*/
    if ((command = (unsigned char *) malloc(commandLength + 1)) == NULL) {
        syslog (LOG_ERR, "command malloc failed: %m");
        goto err;
    }

    memset(command, 0, ((commandLength) + 1));

    /*Wait max 2 seconds for data coming from client, otherwise exits with error.*/
    if (receive_from_socket (socket, command, commandLength, timeout, utimeout) < 0)
        goto err;


    /*3. RESULTS*/	
    if (fork_system(socket, command) < 0)
        goto err;

    /*4. WAIT FOR CLIENT TO CLOSE CONNECTION AND FINISH*/
    // We may avoid the TIME_WAIT state in the server side if we always wait for the client to close the connection.
    // Never use SO_LINGER!!! The client should be able to know when there are no more data. The protocol
    // (application level) should notify the client when the server ended up sending data and in this
    // way the client is able to close the connection.
    // See:
    // http://blog.netherlabs.nl/articles/2009/01/18/the-ultimate-so_linger-page-or-why-is-my-tcp-not-reliable
    // http://www.serverframework.com/asynchronousevents/2011/01/time-wait-and-its-design-implications-for-protocols-and-scalable-servers.html
    // http://stackoverflow.com/questions/3757289/tcp-option-so-linger-zero-when-its-required
    if (wait_for_closed_socket(socket, timeout) < 0)
        syslog (LOG_ERR, "client did not close connection in time");


err:
    free(command);
    close(socket);

    pthread_exit(0);
}



int required_sock_options (int socket)
{
    int optval, flags;

    /*We want non blocking sockets.*/
    /*See the discussion of spurious readiness notifications under the BUGS section of select(2) */
    if ((flags = TEMP_FAILURE_RETRY(fcntl(socket,F_GETFL,0))) < 0) {
        syslog (LOG_ERR, "read socket status flags failed: %m");
        return -1;
    }

    if (TEMP_FAILURE_RETRY(fcntl(socket, F_SETFL, O_NONBLOCK|flags)) < 0){
        syslog (LOG_ERR, "set socket status flags failed: %m");
        return -1;
    }

    /*Portable programs should not rely on inheritance or noninheritance of file status flags and */
    /*always explicitly set all required flags*/
    optval = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        syslog (LOG_ERR, "setsockopt SO_REUSEADDR failed: %m");
        return -1;
    }

    /*Enable keepalive for this socket*/
    optval = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
        syslog (LOG_ERR, "setsockopt SO_KEEPALIVE failed: %m");
        return -1;
    }

    /*
     *TODO: keepalive is not enough to find out if the connection is broken
     *      apparently it just works while the handshake phase. See:
     *      http://stackoverflow.com/questions/4345415/socket-detect-connection-is-lost
     *      I have to implement an echo/ping messages protocol (application layer)
     */

    return 0;
}



int readable_timeout (int fd, long timeout, long utimeout)
{
    struct timeval ptime;   /*Timeout, secs and usecs*/
    fd_set fd_read;         /*Values for select function.*/
    int ret;                /*Store return value from select.*/

    ptime.tv_sec = timeout;
    ptime.tv_usec = utimeout;
    FD_ZERO(&fd_read);
    FD_SET(fd, &fd_read);
  
    ret = TEMP_FAILURE_RETRY(select(fd+1, &fd_read, NULL, NULL, &ptime)); 
    
    if (ret == 0) {
        syslog(LOG_INFO, "receiving timeout error: %m");
        return -1;
    } else if (ret == -1) {
        syslog(LOG_ERR, "receiving error: %m");
        return -1;
    }

    return ret;
}



int readable (int socket, unsigned char *data, int len, int flags)
{
    int received;   /*Stores received data from socket*/

    received = TEMP_FAILURE_RETRY(recv(socket, data, len, flags));

    if (received < 0) {
        if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
            syslog (LOG_ERR, "read TCP socket failed: %m");
            received = -1;
        } else {
            /*see spurious readiness man select(2) BUGS section*/
            syslog (LOG_INFO, "read TCP socket spurious readiness");
            received = 0;
        }
    } else if (received == 0) {
        /*if received is 0, client closed connection but we wanted to receive more data, */
        /*this is an error */
        syslog (LOG_ERR, "expected more data, closed connection from client");
        received = -1;
    }

    return received;
}



int receive_from_socket (int socket, unsigned char *data, int len, long timeout, long utimeout)
{
    int nData, iPos;	/*Control variables.*/

    nData = iPos = 0;
    do {
        if (readable_timeout(socket, timeout, utimeout) < 0)
            return -1;
        
        if ((nData = readable (socket, &data[iPos], len, 0)) < 0)
            return -1;

        len -= nData;
        iPos += nData;
    } while (len > 0);

    return 0;
}



int is_closed_socket (int socket)
{
    int isClosed;   /*Stores received data from socket. We expect 0 data from client (closed connection)*/
    unsigned char dummyData[10];
    int dummyLen;
    int dummyFlags;

    dummyLen = 10;
    dummyFlags = 0;

    isClosed = TEMP_FAILURE_RETRY(recv(socket, dummyData, dummyLen, dummyFlags));

    if (isClosed < 0) {
        if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
            syslog (LOG_ERR, "read TCP socket failed: %m");
            isClosed = -1;
        } else {
            /*see spurious readiness man select(2) BUGS section*/
            syslog (LOG_INFO, "read TCP socket spurious readiness");
            isClosed = -1;
        }
    } else if (isClosed > 0) {
        /*client should not have sent any data */
        /*this is an error */
        syslog (LOG_ERR, "unexpected data from client");
        isClosed = -1;
    }

    return isClosed;
}



int wait_for_closed_socket (int socket, long timeout)
{
    time_t start_t, end_t;
    double diff_t;

    do {
        time(&start_t);

        if (readable_timeout(socket, timeout, 0) < 0)
            return -1;

        if (is_closed_socket(socket) == 0)
            return 0;

        time(&end_t);
        diff_t = difftime(end_t, start_t);
        timeout -= diff_t;

    } while (timeout > 0);

    return -1;
}






int polite_kill_and_wait(pid_t pid)
{
    if (kill(pid, SIGTERM) < 0) {
        syslog (LOG_ERR, "error while sending SIGTERM to child process: %m");
        return -1;
    }

    sleep(5);

    // It might be interesting to use if/ else if/ else if/ to write error log when waitpid returns -1 and 0.
    // In this case when -1 or 0 I am using the same LOG_ERR (see the next call to syslog just below)
    // the problem is, when -1 the error is different than when 0. Perhaps it would be interesting to show a different
    // error log when -1 and when 0.
    if (TEMP_FAILURE_RETRY(waitpid(pid, NULL, WNOHANG)) > 0) {
        // Child process is dead.
        return 0;
    }

    syslog (LOG_ERR, "waitpid after SIGTERM did not work, next step trying with SIGKILL: %m");

    if (kill(pid, SIGKILL) < 0) {
        syslog (LOG_ERR, "error while sending SIGKILL to child process: %m");
        return -1;
    }

    sleep(5);

    if (TEMP_FAILURE_RETRY(waitpid(pid, NULL, WNOHANG)) > 0) {
        // Child process is dead.
        return 0;
    }

    /*We are not sure if the child process is dead. In this case, */
    /*probably the child process is going to be an orphan one. */
    syslog (LOG_ERR, "waitpid after SIGKILL did not work either: %m");

    return -1;
}



int fork_system(int socket, unsigned char *command)
{
    pid_t pid;              /*Child or parent PID.*/
    int out[2], err[2];     /*Store pipes file descriptors. Write ends attached to the stdout*/
                            /*and stderr streams.*/
    u_char buf[2000];       /*Read data buffer. allignment(int) * 500.*/
    struct pollfd polls[2]; /*pipes attached to the stdout and stderr streams.*/
    int n;                  /*characters number from stdout and stderr*/
    struct tcpforkhdr *header = (struct tcpforkhdr *)buf;
    /*Value by default*/
    int childreturnstatus = -1;
    int returnValue = 0;    /*return value from this function can be caught by upper layers,*/
                            /*OK by default*/
    sigset_t unBlockMask;   /*Used by the child process in order to unblock the SIGCHLD signal, which was blocked by the main process.*/
    int pollReturn;
    char **args;



	
    out[0] = out[1] = err[0] = err[1]  = -1;


    /*Creating pipes, they will be attached to the stderr and stdout streams*/	
    if (pipe(out) < 0 || pipe(err) < 0) {
        syslog (LOG_ERR, "pipe failed: %m");
        goto err;
    }

    if ((pid=fork()) == -1) {
        syslog (LOG_ERR, "fork failed: %m");
        goto err;
    }

    if (pid == 0) {
        /*Child process*/

        /*Unblock SIGCHLD*/
        // From man sigaction(2):
        // A child created via fork(2) inherits a copy of its parent's signal dispositions.
        // From man execve(2):
        // * The dispositions of any signals that are being caught (handled signals) are reset to the default (signal(7))
        // So, the signal handlers are not inherited!! Using the clone function directly, wich is used by execv* functions, you could do more things
        // (even inherit signal handlers) but never use the clone function!!
        // * POSIX.1-2001 specifies that the dispositions of any signals that are ignored or set to the default are left unchanged. POSIX.1-2001
        // specifies one exception: if SIGCHLD is being ignored, then an implementation may leave the disposition unchanged or reset it to the
        // default; Linux does the former.
        // Then, SIG_IGN and SIG_DFL are inherited!!
        // From man sigprocmask(2):
        // A child created via fork(2) inherits a copy of its parent's signal mask; the signal mask is preserved across execve(2).
        // This is why I must unblock SIGCHLD!!
        if (sigemptyset(&unBlockMask) < 0) {
            syslog (LOG_ERR, "Unblock SIGCHLD empty mask: %m");
            /*Going to zombie state, hopefully waitpid will catch it*/
            _exit(EXIT_FAILURE);
        }
        if (sigaddset(&unBlockMask, SIGCHLD) <0) {
            syslog (LOG_ERR, "Unblock SIGCHLD sigaddset mask: %m");
            /*Going to zombie state, hopefully waitpid will catch it*/
            _exit(EXIT_FAILURE);
        }
        /*Should I use pthread_sigmask?*/
        if (sigprocmask(SIG_UNBLOCK, &unBlockMask, NULL) == -1) {
            syslog (LOG_ERR, "Unblock sigprocmask failed: %m");
            /*Going to zombie state, hopefully waitpid will catch it*/
            _exit(EXIT_FAILURE);
        }

        /*Attach stderr and stdout streams to my pipes (their write end)*/
        if ((TEMP_FAILURE_RETRY(dup2(out[1], 1)) < 0) || (TEMP_FAILURE_RETRY(dup2(err[1], 2)) < 0)) {	
            syslog (LOG_ERR, "child dup2 failed: %m");
            /*Going to zombie state, hopefully waitpid will catch it*/	
            _exit(EXIT_FAILURE);
        }

        /*Close useless file descriptors. The child inherits copies of the parent's set of open file descriptors. See as well: CLOEXEC*/
        close (out[0]);
        close (out[1]);
        close (err[0]);
        close (err[1]);
        close (sockfd);
        close (socket);

        args = create_args(command);
        if (args == NULL) {
            syslog (LOG_ERR, "create args error: %m");
            /*Going to zombie state, hopefully waitpid will catch it*/
            _exit(EXIT_FAILURE);
        }

        if (args[0] == NULL) {
            syslog (LOG_ERR, "command not found: %m");
            /*Going to zombie state, hopefully waitpid will catch it*/
            _exit(EXIT_FAILURE);
        }

        if (execvp(args[0], (char **) args) < 0) {
            syslog (LOG_ERR, "execvp error: %m");
            /*Going to zombie state, hopefully waitpid will catch it*/
            _exit(EXIT_FAILURE);
        }
    }
    else {
        /*Parent process*/
        /*It sends data to the Java client using a TCP connection.*/
        /*TODO: close the write end of my pipes.*/

        /*Attach pipes' read end to pollfd*/
        polls[0].fd=out[0];
        polls[1].fd=err[0];
        polls[0].events = polls[1].events = POLLIN;

        for (;;) {
            pollReturn = poll(polls, 2, 100);
            if(pollReturn > 0) {
                if(polls[0].revents && POLLIN) {
                    memset(buf, 0, 2000);
                    n=TEMP_FAILURE_RETRY(read(out[0], &buf[sizeof(struct tcpforkhdr)], 2000-sizeof(struct tcpforkhdr)));
                    //To network order, indeed it is the order used by Java (BIG ENDIAN). Anyway I am 
                    //swapping the bytes because it is required if you want to write portable code and 
                    //ENDIANNESS indepedent.
                    header->type = htonl(1);
                    header->length = htonl(n);
                    //PACKING THE STRUCT OR SERIALIZING? 
                    //serializing-> sends the struct one data member at time (using for example writev?) I send
                    //one field of my struct at time.
                    //packing-> Compilers often do some amount of padding and alignment, so unless you define 
                    //alignment explicitly (maybe using a #pragma pack()), that size may be different. 

                    //I think I do not need any of both, because my struct has no padding and it has a defined size
                    //are you sure ur struct is never going to have padding? if it is unaligned? could my struct be unaligned?
                    //does the compiler guarantee alignment?

                    //I do not care about the ENDIANNESS and character set in the payload, I send bytes
                    //and the client application must know what it has to do with them. 
                    //TODO: my own protocol to make the client independent of the ENDIANNESS and character set used
                    //by the machine running this server. See comments in the TCPForkDaemon.java code about this.

                    // Avoid SIGPIPE with MSG_NOSIGNAL flag. It just works on Linux OS (non portable code)
                    // Portable alternatives: sighandler for SIGPIPE or block/ignore SIGPIPE.
                    // There is SIGPIPE JUST when using send/write (no with read/recv) and remote side closed connection.
                    if (TEMP_FAILURE_RETRY(send(socket, buf, n+sizeof(struct tcpforkhdr), MSG_NOSIGNAL)) < 0) {
                        syslog (LOG_INFO, "error while sending stdout: %m");
                        polite_kill_and_wait(pid);
                        goto err;
                    }
                }
 
                if(polls[1].revents && POLLIN) {
                    memset(buf, 0, 2000);
                    n=TEMP_FAILURE_RETRY(read(err[0], &buf[sizeof(struct tcpforkhdr)], 2000-sizeof(struct tcpforkhdr)));
                    header->type = htonl(2);
                    header->length = htonl(n);

                    // Avoid SIGPIPE with MSG_NOSIGNAL flag. It just works on Linux OS (non portable code)
                    // Portable alternatives: sighandler for SIGPIPE or block/ignore SIGPIPE.
                    // There is SIGPIPE JUST when using send/write (no with read/recv) and remote side closed connection.
                    if (TEMP_FAILURE_RETRY(send(socket, buf, n+sizeof(struct tcpforkhdr), MSG_NOSIGNAL)) < 0) {
                        syslog (LOG_INFO, "error while sending stderr: %m");
                        polite_kill_and_wait(pid);
                        goto err;
                    }
                }

                if(!(polls[0].revents && POLLIN) && !(polls[1].revents && POLLIN)) {
                    syslog (LOG_ERR, "parent error polling pipes: %m");
                    polite_kill_and_wait(pid);
                    /*In the Java code, the client will get an error as the return status from the exec method.*/
                    goto err;
                }
            }   
            else if (pollReturn == 0) {
                /*When timeout*/
                int waitpidReturn;
                int status;
                waitpidReturn = TEMP_FAILURE_RETRY(waitpid(pid, &status, WNOHANG));
                if(waitpidReturn > 0) {
                    /*Child is dead, we can finish the connection*/

                    /*First of all, we check the exit status of our child process*/
                    if (WIFEXITED(status)) {
                        /* The child exited normally; get its exit code.*/
                        childreturnstatus = WEXITSTATUS(status);
                    }
                    else {
                        /*In case of error send an error status to the remote calling process*/
                        childreturnstatus = -1;
                    }
                    break;
                }
                else if(waitpidReturn < 0) {
                    // Error when using waitpid function
                    syslog (LOG_ERR, "waitpid error after poll timeout from child process: %m");
                    polite_kill_and_wait(pid);
                    goto err;
                }

                /*The child process is not dead, keep polling more data from stdout or stderr streams*/
            }
            else {
                /*Return with error from poll*/
                syslog (LOG_ERR, "poll error: %m");
                polite_kill_and_wait(pid);
                goto err;
            }
        }
    }
    
end:
    memset(buf, 0, 2000);
    header->type = htonl(3);
    header->length = htonl((childreturnstatus));
    // Avoid SIGPIPE with MSG_NOSIGNAL flag. It just works on Linux OS (non portable code)
    // Portable alternatives: sighandler for SIGPIPE or block/ignore SIGPIPE.
    // There is SIGPIPE JUST when using send/write (no with read/recv) and remote side closed connection.
    if (TEMP_FAILURE_RETRY(send(socket, buf, sizeof(struct tcpforkhdr), MSG_NOSIGNAL)) < 0)
        syslog (LOG_INFO, "error while sending return status: %m");

    close (out[0]);
    close (out[1]);
    close (err[0]);
    close (err[1]);
    return returnValue;
err:
    childreturnstatus = -1;
    returnValue = -1;
	goto end;
}



char* create_arg(char * token)
{
    size_t arg_len;
    char * arg;
    arg_len = strlen(token);

    if((arg = (char *)(malloc(sizeof(char) * (arg_len + 1)))) == NULL ) {
        syslog (LOG_ERR, "create arg malloc error: %m");
        return NULL;
    }
    memset(arg, 0, arg_len + 1);
    memcpy(arg, token, arg_len);

    return arg;
}



char** create_args(char *command)
{
    unsigned int ARGS_SIZE = 50;
    char delim[] = " \t\n\r\f";
    char *token;
    char **args;
    char *arg;
    int args_count = 0;
    int index;

    if ((args = (char *) malloc(sizeof(char *) * ARGS_SIZE)) == NULL) {
        syslog (LOG_ERR, "init args malloc error: %m");
        return NULL;
    }

    token = strtok(command, delim);

    while (token != NULL) {
        if ((arg = create_arg(token)) == NULL) {
            syslog (LOG_ERR, "create arg error: %m");
            goto err;
        }
        args[args_count] = arg;

        args_count += 1;

        if (args_count >= ARGS_SIZE) {
            // TODO: check UINT_MAX limit
            ARGS_SIZE = ARGS_SIZE + 100;

            if ((args = (char *) realloc(args, sizeof(char *) * ARGS_SIZE)) == NULL) {
                syslog (LOG_ERR, "create args realloc error: %m");
                goto err;
            }
        }

        token = strtok(NULL, delim);
    }

    args[args_count] = NULL;
end:
    return args;
err:
    /*Release memory.*/
    for (index = (args_count - 1); index >= 0; index--) {
        free(args[index]);
    }
    free(args);
    /*Return error.*/
    args = NULL;
    goto end;
}



void sigint_handler(int sig)
{
    if (daemonPID != getpid()) {
        //Do nothing
        return;
    }


    close (sockfd);
    /*TODO: kill child processes, finish threads and release allocate memory*/
    /* From http://www.cons.org/cracauer/sigint.html
     * Since a shellscript may in turn be called by a shellscript, you need to make sure that you properly
     * communicate the discontinue intention to the calling program. WIFSIGNALED(status) and WTERMSIG(status)
     * tell whether the child says "I exited on SIGINT". These values are used by the shell to discontinue
     * the whole shell script in execution. If I use exit the shell has no way to know the user pressed Ctrl-C
     * in order to stop the shell script in execution. This has just meaning when this program is executed in a shell script
     * but because I do not know how the user is going to use it I must always finish every SIGINT handler in this way.
     * So from a handler for SIGINT I must always finish with kill(SIGINT, SIG_DFL) (default kills the application)
     */
    if (sigaction(SIGINT, &sigintAction, NULL) < 0) {
        syslog (LOG_ERR, "SIGINT restore signal handler failed: %m");
        /* man 7 signal
         * Async-signal-safe functions
         * A signal handler function must be very careful, since processing elsewhere may be interrupted at some arbitrary
         * point in the execution of the program.  POSIX has the concept of "safe  function". If a signal interrupts the
         * execution of an unsafe function, and handler calls an unsafe function, then the behavior of the program is undefined.
         *
         * From sig handler I MAY USE JUST _exit
         */
        _exit (EXIT_FAILURE);
    }
    kill(getpid(), SIGINT);
}
