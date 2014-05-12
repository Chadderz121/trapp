/* trapp_test.c
 *  by Alex Chadwick
 *
 * User land test of the /dev/trapp security module.
 */

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>

#include "../module/trapp.h"

int main(int argc, const char *argv[]) {
	int trapp_fd = -1;
	int socket_fd = -1;
	int ret = -1;
	int challenger;
	int i;
	if (argc != 2)
		return -1;
	struct sockaddr_in myaddr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(0x7f000001), /* 127.0.0.1 */
		.sin_port = htons(9876),
	};
	struct sockaddr_in otaddr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(0x7f000001), /* 127.0.0.1 */
		.sin_port = htons(9875),
	};

	if (*argv[1] == 'c') {
		unsigned short temp = otaddr.sin_port;
		printf("challenger.\n");
		otaddr.sin_port = myaddr.sin_port;
		myaddr.sin_port = temp;
		challenger = 1;
	} else if (*argv[1] == 't') {
		printf("challenged.\n");
		challenger = 0;
	} else
		return -1;

	printf("opening " TRAPP_FS "\n");
	trapp_fd = open(TRAPP_FS);
	if (trapp_fd < 0) {
		perror("couldn't open file.");
		goto out;
	}

	printf("creating socket\n");
	socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (socket_fd < 0) {
		perror("couldn't create socket.");
		goto out;
	}

	printf("binding socket\n");
	if (bind(socket_fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		perror("couldn't bind socket.");
		goto out;
	}

	// now for the trapp bit
	if (challenger) {
		printf("send challenge\n");
		for (i = 0; i < 20; i++)
		{
			struct trapp_challenge_t challenge = {
				.socket_fd = socket_fd,
				.socket_addr = &otaddr,
				.socket_addr_len = sizeof(otaddr),
				.application = 0,
				.application_version = 0,
			};
			ret = ioctl(trapp_fd, IOCTL_SEND_CHALLENGE, &challenge);
			if (ret < 0) {
				printf("%d err[%d]\n", challenge.status, challenge.error);
				printf("trapp failed. %s (%d)\n", strerror(-ret), -ret);
				goto out;
			}
			printf("%.3fms\n", challenge.duration / 1000000.0f);
		}
	} else {
		printf("receive challenge\n");
		for (i = 0; i < 20; i++)
		{
			struct trapp_challenge_t challenge = {
				.socket_fd = socket_fd,
				.socket_addr = &otaddr,
				.socket_addr_len = sizeof(otaddr),
				.application = 0,
				.application_version = 0,
			};
			ret = ioctl(trapp_fd, IOCTL_RECV_CHALLENGE, &challenge);
			if (ret < 0) {
				printf("%d err[%d]\n", challenge.status, challenge.error);
				printf("trapp failed. %s (%d)\n", strerror(-ret), -ret);
				goto out;
			}
			printf("%.3fms\n", challenge.duration / 1000000.0f);
		}
	}

	ret = 0;
out:
	if (socket_fd >= 0)
		close(socket_fd);
	if (trapp_fd != -1)
		close(trapp_fd);
	return 0;
}
