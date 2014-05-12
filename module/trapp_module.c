/* trapp_module.c
 *  by Alex Chadwick
 *
 * Linux kernel module for /dev/trapp
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "trapp.h"

#include <asm/uaccess.h>
#include <linux/aio.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/time.h>

#include "checkfn_c.h"
#include "checkfn_asm.h"

#ifdef TRAPP_DEBUG
#define LOG_DEBUG(x, ...) printk(KERN_INFO x, ## __VA_ARGS__)
#else
#define LOG_DEBUG(x, ...) ((void)0)
#endif

static int trapp_open(struct inode *inode, struct file *file);
static int trapp_release(struct inode *inode, struct file *file);
static long trapp_ioctl(struct file *file, unsigned int ioctl_num,
	unsigned long ioctl_param);

static struct file_operations trapp_ops = {
	.unlocked_ioctl = trapp_ioctl,
	.open = trapp_open,
	.release = trapp_release,
};

static int trapp_dev;

static int __init trapp_init(void) {
	int ret;

	LOG_DEBUG("trap_init()\n");
	LOG_DEBUG("packet sizes[helo %d, test %d, ansr %d, rslt %d]\n",
		TRAPP_PACKET_LENGTH(helo), TRAPP_PACKET_LENGTH(test), 
		TRAPP_PACKET_LENGTH(ansr), TRAPP_PACKET_LENGTH(rslt));
	ret = register_chrdev(248, TRAPP_DEV_NAME, &trapp_ops);
	
	if (ret < 0) {
		printk(KERN_ALERT "trapp failed to register device."
			" Error %d.\n", ret);
		return ret;
	}
	trapp_dev = ret;
	LOG_DEBUG("trapp registered as device %d.\n", trapp_dev);
	
	return 0;
}

static void __exit trapp_exit(void) {
	LOG_DEBUG("trap_exit()\n");
	unregister_chrdev(248, TRAPP_DEV_NAME);
}

module_init(trapp_init);
module_exit(trapp_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Alex Chadwick <awc32@cam.ac.uk>");
MODULE_DESCRIPTION("trapp network security module");

static int trapp_open(struct inode *inode, struct file *file) {
	LOG_DEBUG("trapp_open()\n");
	try_module_get(THIS_MODULE);
	return 0;
}

static int trapp_release(struct inode *inode, struct file *file) {
	LOG_DEBUG("trapp_release()\n");
	module_put(THIS_MODULE);
	return 0;
}

static long trapp_send_challenge(struct trapp_challenge_t __user *params);
static long trapp_recv_challenge(struct trapp_challenge_t __user *params);

static long trapp_ioctl(struct file *file, unsigned int ioctl_num,
	unsigned long ioctl_param) {
	LOG_DEBUG("trapp_ioctl(%u, %lu)\n", ioctl_num, ioctl_param);

	switch (ioctl_num) {
		case IOCTL_SEND_CHALLENGE: {
			LOG_DEBUG("IOCTL_SEND_CHALLENGE\n");
			return trapp_send_challenge(
				(struct trapp_challenge_t __user *)ioctl_param);
		}
		case IOCTL_RECV_CHALLENGE: {
			LOG_DEBUG("IOCTL_RECV_CHALLENGE\n");
			return trapp_recv_challenge(
				(struct trapp_challenge_t __user *)ioctl_param);
		}
		default: {
			printk(KERN_ALERT "Unknown trapp ioctl.\n");
			return -EINVAL;
		}
	}
}

static int trapp_report_status(struct trapp_challenge_t __user *params,
	struct trapp_challenge_t *challenge, enum trapp_status_t status) {
	challenge->status = status;
	if (copy_to_user(params, challenge, sizeof(struct trapp_challenge_t)))
		return -1;
	return 0;
}

static int trapp_report_error(struct trapp_challenge_t __user *params,
	struct trapp_challenge_t *challenge, enum trapp_error_t error) {
	challenge->status = TRAPP_STATUS_ERROR;
	challenge->error = error;
	if (copy_to_user(params, challenge, sizeof(struct trapp_challenge_t)))
		return -1;
	return 0;
}

static int trapp_socket_get(
	struct trapp_challenge_t __user *params,
	struct trapp_challenge_t *challenge, struct socket **sock,
	struct msghdr *msg) {
	int ret;
	
	LOG_DEBUG("copy user address\n");
	if (challenge->socket_addr && challenge->socket_addr_len < 0) {
		trapp_report_error(params, challenge, TRAPP_ERROR_ARG);
		return -ERANGE;
	}
	if (!challenge->socket_addr || challenge->socket_addr_len == 0) {
		msg->msg_name = NULL;
		msg->msg_namelen = 0;
	} else {
		LOG_DEBUG("allocating for user address\n");
		msg->msg_name = kmalloc(challenge->socket_addr_len, GFP_KERNEL);
		if (!msg->msg_name) {
			trapp_report_error(params, challenge, TRAPP_ERROR_IO);
			return -ENOMEM;
		}
		if (copy_from_user(msg->msg_name,
			(void __user *)challenge->socket_addr,
			challenge->socket_addr_len)) {
			trapp_report_error(params, challenge, TRAPP_ERROR_IO);
			return -EIO;
		}			
		msg->msg_namelen = challenge->socket_addr_len;
	}

	LOG_DEBUG("find user socket\n");
	*sock = sockfd_lookup(challenge->socket_fd, &ret);
	if (!*sock) {
		trapp_report_error(params, challenge, TRAPP_ERROR_ARG);
		return ret;
	}
	return 0;
}

static int trapp_socket_sendmsg(struct socket *sock, struct msghdr *msghdr,
	void *msg, size_t msg_len) {
	struct kvec iov = {
		.iov_base = msg,
		.iov_len = msg_len,
	};
	
	msghdr->msg_flags = 0;
	LOG_DEBUG("Send %d byte message to %08x:%hu\n", msg_len,
		ntohl(msghdr->msg_name ? ((uint32_t *)msghdr->msg_name)[1] : 0),
		ntohs(msghdr->msg_name ? ((uint16_t *)msghdr->msg_name)[1] : 0));
	return kernel_sendmsg(sock, msghdr, &iov, 1, msg_len);	
}
static int trapp_socket_recvmsg(struct socket *sock, struct msghdr *msghdr,
	void *msg, size_t msg_len) {
	struct kvec iov = {
		.iov_base = msg,
		.iov_len = msg_len,
	};
	struct msghdr rcv;
	int ret;
	
	memset(&rcv, 0, sizeof(rcv));
	LOG_DEBUG("Waiting for message.\n");
	ret = kernel_recvmsg(sock, &rcv, &iov, 1, msg_len, MSG_WAITALL);
	if (ret < 0)
		return ret;
	
	LOG_DEBUG("Received %d byte message from %08x:%hu\n", ret, 
		ntohl(rcv.msg_name ? ((uint32_t *)rcv.msg_name)[1] : 0),
		ntohs(rcv.msg_name ? ((uint16_t *)rcv.msg_name)[1] : 0));

	return ret;
}

#define ADDR_COUNT 1

static int trapp_challenger_send_helo(struct trapp_challenge_t *challenge,
	struct socket *sock, struct msghdr *msghdr) {
	struct trapp_packet_t packet;
	int ret;

	LOG_DEBUG("challenger send helo\n");
	packet.header.magic = TRAPP_PACKET_HELO;
	packet.header.length = TRAPP_PACKET_LENGTH(helo);
	packet.body.helo.system = TRAPP_HELO_SYSTEM_RPI;
	packet.body.helo.version = TRAPP_HELO_VERSION_CURRENT;
	packet.body.helo.application = challenge->application;
	packet.body.helo.application_version = challenge->application_version;
	packet.body.helo.role = TRAPP_HELO_ROLE_CHALLENGER;

	ret = trapp_socket_sendmsg(sock, msghdr, &packet,
		TRAPP_PACKET_LENGTH(helo));
	if (ret != TRAPP_PACKET_LENGTH(helo))
		return (ret < 0 ? ret : -EIO);
	return 0;
}
static int trapp_challenger_recv_helo(struct trapp_challenge_t *challenge,
	struct socket *sock, struct msghdr *msghdr) {
	struct trapp_packet_t packet;
	int ret;
	
	LOG_DEBUG("challenger receive helo\n");
	ret = trapp_socket_recvmsg(sock, msghdr, &packet,
		TRAPP_PACKET_LENGTH(helo));
	if (ret != TRAPP_PACKET_LENGTH(helo))
		return (ret < 0 ? ret : -EBADMSG);

	if (packet.header.magic != TRAPP_PACKET_HELO) return -EBADMSG;
	if (packet.header.length != TRAPP_PACKET_LENGTH(helo)) return -EBADMSG;
	if (packet.body.helo.system != TRAPP_HELO_SYSTEM_RPI) return -EBADMSG;
	if (packet.body.helo.version != TRAPP_HELO_VERSION_CURRENT)
		return -EBADMSG;
	if (packet.body.helo.application != challenge->application)
		return -EBADMSG;
	if (packet.body.helo.application_version !=
		challenge->application_version) return -EBADMSG;
	if (packet.body.helo.role != TRAPP_HELO_ROLE_CHALLENGEE)
		return -EBADMSG;
	return 0;
}
static int trapp_challenger_send_test(struct trapp_challenge_t *challenge,
	struct socket *sock, struct msghdr *msghdr, uint32_t iterations,
	const uint32_t seed[8]) {
	struct trapp_packet_t packet;
	int ret;

	LOG_DEBUG("challenger send test\n");
	packet.header.magic = TRAPP_PACKET_TEST;
	packet.header.length = TRAPP_PACKET_LENGTH(test);
	packet.body.test.iterations = iterations;
	memcpy(packet.body.test.seed, seed, sizeof(packet.body.test.seed));

	ret = trapp_socket_sendmsg(sock, msghdr, &packet,
		TRAPP_PACKET_LENGTH(test));
	if (ret != TRAPP_PACKET_LENGTH(test))
		return (ret < 0 ? ret : -EIO);
	return 0;
}
static int trapp_challenger_recv_ansr(struct trapp_challenge_t *challenge,
	struct socket *sock, struct msghdr *msghdr, uint32_t result[8],
	uint32_t *addrs) {
	char buffer[TRAPP_PACKET_LENGTH(ansr) + sizeof(uint32_t) * ADDR_COUNT];
	struct trapp_packet_t *packet = (void *)buffer;
	int ret;
	
	LOG_DEBUG("challenger receive ansr\n");
	ret = trapp_socket_recvmsg(sock, msghdr, packet,
		TRAPP_PACKET_LENGTH(ansr) + sizeof(uint32_t) * ADDR_COUNT);
	if (ret != TRAPP_PACKET_LENGTH(ansr) + sizeof(uint32_t) * ADDR_COUNT)
		return (ret < 0 ? ret : -EBADMSG);

	if (packet->header.magic != TRAPP_PACKET_ANSR) return -EBADMSG;
	if (packet->header.length != TRAPP_PACKET_LENGTH(ansr) +
		sizeof(uint32_t) * ADDR_COUNT) return -EBADMSG;
	if (packet->body.ansr.addr_count != ADDR_COUNT) return -EBADMSG;
	memcpy(result, packet->body.ansr.hash, sizeof(packet->body.ansr.hash));
	memcpy(addrs, packet->body.ansr.addrs, sizeof(uint32_t) * ADDR_COUNT);
	return 0;
}
static int trapp_challenger_send_rslt(struct trapp_challenge_t *challenge,
	struct socket *sock, struct msghdr *msghdr, uint32_t result,
	uint64_t duration) {
	struct trapp_packet_t packet;
	int ret;

	LOG_DEBUG("challenger send rslt\n");
	packet.header.magic = TRAPP_PACKET_RSLT;
	packet.header.length = TRAPP_PACKET_LENGTH(rslt);
	packet.body.rslt.result = result;
	packet.body.rslt.duration = duration;

	ret = trapp_socket_sendmsg(sock, msghdr, &packet,
		TRAPP_PACKET_LENGTH(rslt));
	if (ret != TRAPP_PACKET_LENGTH(rslt))
		return (ret < 0 ? ret : -EIO);
	return 0;
}

static int trapp_challengee_send_helo(struct trapp_challenge_t *challenge,
	struct socket *sock, struct msghdr *msghdr) {
	struct trapp_packet_t packet;
	int ret;

	LOG_DEBUG("challengee send helo\n");
	packet.header.magic = TRAPP_PACKET_HELO;
	packet.header.length = TRAPP_PACKET_LENGTH(helo);
	packet.body.helo.system = TRAPP_HELO_SYSTEM_RPI;
	packet.body.helo.version = TRAPP_HELO_VERSION_CURRENT;
	packet.body.helo.application = challenge->application;
	packet.body.helo.application_version = challenge->application_version;
	packet.body.helo.role = TRAPP_HELO_ROLE_CHALLENGEE;

	ret = trapp_socket_sendmsg(sock, msghdr, &packet,
		TRAPP_PACKET_LENGTH(helo));
	if (ret != TRAPP_PACKET_LENGTH(helo))
		return (ret < 0 ? ret : -EIO);
	return 0;
}
static int trapp_challengee_recv_helo(struct trapp_challenge_t *challenge,
	struct socket *sock, struct msghdr *msghdr) {
	struct trapp_packet_t packet;
	int ret;
	
	LOG_DEBUG("challengee receive helo\n");
	ret = trapp_socket_recvmsg(sock, msghdr, &packet,
		TRAPP_PACKET_LENGTH(helo));
	if (ret != TRAPP_PACKET_LENGTH(helo))
		return (ret < 0 ? ret : -EBADMSG);

	if (packet.header.magic != TRAPP_PACKET_HELO) return -EBADMSG;
	if (packet.header.length != TRAPP_PACKET_LENGTH(helo)) return -EBADMSG;
	if (packet.body.helo.system != TRAPP_HELO_SYSTEM_RPI) return -EBADMSG;
	if (packet.body.helo.version != TRAPP_HELO_VERSION_CURRENT)
		return -EBADMSG;
	if (packet.body.helo.application != challenge->application)
		return -EBADMSG;
	if (packet.body.helo.application_version !=
		challenge->application_version) return -EBADMSG;
	if (packet.body.helo.role != TRAPP_HELO_ROLE_CHALLENGER)
		return -EBADMSG;
	return 0;
}
static int trapp_challengee_recv_test(struct trapp_challenge_t *challenge,
	struct socket *sock, struct msghdr *msghdr, uint32_t *iterations,
	uint32_t seed[8]) {
	struct trapp_packet_t packet;
	int ret;
	
	LOG_DEBUG("challengee receive test\n");
	ret = trapp_socket_recvmsg(sock, msghdr, &packet,
		TRAPP_PACKET_LENGTH(test));
	if (ret != TRAPP_PACKET_LENGTH(test))
		return (ret < 0 ? ret : -EBADMSG);

	if (packet.header.magic != TRAPP_PACKET_TEST) return -EBADMSG;
	if (packet.header.length != TRAPP_PACKET_LENGTH(test)) return -EBADMSG;
	*iterations = packet.body.test.iterations;
	memcpy(seed, packet.body.test.seed, sizeof(packet.body.test.seed));

	return 0;
}
static int trapp_challengee_send_ansr(struct trapp_challenge_t *challenge,
	struct socket *sock, struct msghdr *msghdr, uint32_t result[8],
	uint32_t *addrs) {
	char buffer[TRAPP_PACKET_LENGTH(ansr) + sizeof(uint32_t) * ADDR_COUNT];
	struct trapp_packet_t *packet = (void *)buffer;
	int ret;

	LOG_DEBUG("challengee send ansr\n");
	packet->header.magic = TRAPP_PACKET_ANSR;
	packet->header.length = TRAPP_PACKET_LENGTH(ansr) + sizeof(uint32_t) *
		ADDR_COUNT;
	memcpy(packet->body.ansr.hash, result, sizeof(packet->body.ansr.hash));
	packet->body.ansr.addr_count = ADDR_COUNT;
	memcpy(packet->body.ansr.addrs, addrs, sizeof(uint32_t) * ADDR_COUNT);

	ret = trapp_socket_sendmsg(sock, msghdr, packet,
		TRAPP_PACKET_LENGTH(ansr) + sizeof(uint32_t) * ADDR_COUNT);
	if (ret != TRAPP_PACKET_LENGTH(ansr) + sizeof(uint32_t) * ADDR_COUNT)
		return (ret < 0 ? ret : -EIO);
	return 0;
}
static int trapp_challengee_recv_rslt(struct trapp_challenge_t *challenge,
	struct socket *sock, struct msghdr *msghdr, uint32_t *result,
	uint64_t *duration) {
	struct trapp_packet_t packet;
	int ret;
	
	LOG_DEBUG("challengee receive rslt\n");
	ret = trapp_socket_recvmsg(sock, msghdr, &packet,
		TRAPP_PACKET_LENGTH(rslt));
	if (ret != TRAPP_PACKET_LENGTH(rslt))
		return (ret < 0 ? ret : -EBADMSG);

	if (packet.header.magic != TRAPP_PACKET_RSLT) return -EBADMSG;
	if (packet.header.length != TRAPP_PACKET_LENGTH(rslt)) return -EBADMSG;
	*result = packet.body.rslt.result;
	*duration = packet.body.rslt.duration;

	return 0;
}

static long trapp_send_challenge(struct trapp_challenge_t __user *params) {
	struct trapp_challenge_t challenge;
	struct socket *sock;
	struct msghdr msghdr;
	uint32_t seed[8];
	uint32_t result[8];
	uint32_t addrs[ADDR_COUNT];
	uint32_t cresult[8];
	uint32_t iterations = 1 << 20;
	struct range asm_body = {
		checkfn_asm_body,
		(uint32_t)checkfn_asm_body,
		(uint32_t)checkfn_asm_body_end - (uint32_t)checkfn_asm_body,
	};
	int ret;

	memset(&msghdr, 0, sizeof(msghdr));

	LOG_DEBUG("copy user params\n");
	if (copy_from_user(&challenge, params, sizeof(challenge)))
		return -EIO;
	challenge.attempt_count = 0;
	challenge.duration = 0;
	challenge.error = TRAPP_ERROR_NONE;

	if ((ret = trapp_socket_get(params, &challenge, &sock, &msghdr))) {
		trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
		return ret;
	}

	// handshake
	if (trapp_report_status(params, &challenge, TRAPP_STATUS_HANDSHAKE)) {
		sockfd_put(sock);
		return -EIO;
	}
	if ((ret = trapp_challenger_send_helo(&challenge, sock, &msghdr))) {
		sockfd_put(sock);
		trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
		return ret;
	}
	if ((ret = trapp_challenger_recv_helo(&challenge, sock, &msghdr))) {
		sockfd_put(sock);
		trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
		return ret;
	}

	// send challenge
	for (challenge.attempt_count = 1;
		challenge.attempt_count <= 3;
		challenge.attempt_count++) {
		struct timespec timer_start, timer_stop, timer_diff;
		for (ret = 0; ret < 8; ret++)
			// TODO need crypto secure numbers here
			seed[ret] = prandom_u32();
		getrawmonotonic(&timer_start);
		if ((ret = trapp_challenger_send_test(&challenge, sock, &msghdr,
			iterations, seed))) {
			sockfd_put(sock);
			trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
			return ret;
		}

		if (trapp_report_status(params, &challenge,
			TRAPP_STATUS_CHALLENGE_SENT)) {
			sockfd_put(sock);
			return -EIO;
		}

		if ((ret = trapp_challenger_recv_ansr(&challenge, sock, &msghdr,
			result, addrs))) {
			sockfd_put(sock);
			trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
			return ret;
		}
		getrawmonotonic(&timer_stop);
		timer_diff = timespec_sub(timer_stop, timer_start);
		challenge.duration = timespec_to_ns(&timer_diff);
		LOG_DEBUG("challenge duration %lluns\n", challenge.duration);

		if (trapp_report_status(params, &challenge,
			TRAPP_STATUS_VERIFYING_RESPONSE)) {
			sockfd_put(sock);
			return -EIO;
		}
		memcpy(cresult, seed, sizeof(cresult));
		asm_body.address = addrs[0];
		LOG_DEBUG("checkfn_c(%u, { %08x, %08x, ... }, NULL, 0, 0, { %x, %x })\n", iterations, cresult[0], cresult[1], asm_body.address, asm_body.size);
		checkfn_c(iterations, cresult, NULL, 0, 0, asm_body);
		LOG_DEBUG("results asm{ %08x, %08x, ... }, c{ %08x, %08x, ... }\n", result[0], result[1], cresult[0], cresult[1]);
		if (memcmp(cresult, result, sizeof(cresult))) {
			if ((ret = trapp_challenger_send_rslt(&challenge, sock,
				&msghdr, TRAPP_RSLT_WRONG,
				challenge.duration))) {
				sockfd_put(sock);
				trapp_report_error(params, &challenge,
					TRAPP_ERROR_IO);
				return ret;
			}

			sockfd_put(sock);
			trapp_report_error(params, &challenge,
				TRAPP_ERROR_BAD_SIGNATURE);
			return -EPERM;
		} else {
			if ((ret = trapp_challenger_send_rslt(&challenge, sock,
				&msghdr, TRAPP_RSLT_TRUSTED,
				challenge.duration))) {
				sockfd_put(sock);
				trapp_report_error(params, &challenge,
					TRAPP_ERROR_IO);
				return ret;
			}
			break;	
		}
	}

	sockfd_put(sock);
	
	if (trapp_report_status(params, &challenge, TRAPP_STATUS_VERIFIED)) {
		trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
		return -EIO;
	}

	return 0;
}

static long trapp_recv_challenge(struct trapp_challenge_t __user *params) {
	struct trapp_challenge_t challenge;
	struct socket *sock;
	struct msghdr msghdr;
	uint32_t result[8];
	uint32_t addrs[ADDR_COUNT] = { (uint32_t)checkfn_asm_body };
	uint32_t iterations;
	uint32_t verify_result;
	int ret;

	memset(&msghdr, 0, sizeof(msghdr));

	LOG_DEBUG("copy user params\n");
	if (copy_from_user(&challenge, params, sizeof(challenge)))
		return -EIO;
	challenge.attempt_count = 0;
	challenge.duration = 0;
	challenge.error = TRAPP_ERROR_NONE;

	if ((ret = trapp_socket_get(params, &challenge, &sock, &msghdr))) {
		trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
		return ret;
	}

	if (trapp_report_status(params, &challenge, TRAPP_STATUS_HANDSHAKE)) {
		sockfd_put(sock);
		return -EIO;
	}
	if ((ret = trapp_challengee_recv_helo(&challenge, sock, &msghdr))) {
		sockfd_put(sock);
		trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
		return ret;
	}
	if ((ret = trapp_challengee_send_helo(&challenge, sock, &msghdr))) {
		sockfd_put(sock);
		trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
		return ret;
	}

	for (challenge.attempt_count = 1;
		challenge.attempt_count <= 3;
		challenge.attempt_count++) {
		if (trapp_report_status(params, &challenge,
			TRAPP_STATUS_CHALLENGE_SENT)) {
			sockfd_put(sock);
			return -EIO;
		}
		if ((ret = trapp_challengee_recv_test(&challenge, sock, &msghdr,
			&iterations, result))) {
			sockfd_put(sock);
			trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
			return ret;
		}

		LOG_DEBUG("checkfn_asm(%u, { %08x, %08x, ... }, NULL, 0, 0, { %x, %x })\n", iterations, result[0], result[1], (uint32_t)checkfn_asm_body, (uint32_t)checkfn_asm_body_end - (uint32_t)checkfn_asm_body);
		checkfn_asm(iterations, result, NULL, 0);
		if ((ret = trapp_challengee_send_ansr(&challenge, sock, &msghdr, result,
			addrs))) {
			sockfd_put(sock);
			trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
			return ret;
		}
		if (trapp_report_status(params, &challenge,
			TRAPP_STATUS_VERIFYING_RESPONSE)) {
			sockfd_put(sock);
			return -EIO;
		}

		if ((ret = trapp_challengee_recv_rslt(&challenge, sock, &msghdr,
			&verify_result, &challenge.duration))) {
			sockfd_put(sock);
			trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
			return ret;
		}
		sockfd_put(sock);
		break;
	}

	if (verify_result == TRAPP_RSLT_TRUSTED) {
		if (trapp_report_status(params, &challenge,
			TRAPP_STATUS_VERIFIED)) {
			trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
			return -EIO;
		}
		return 0;
	} else if (verify_result == TRAPP_RSLT_TIMEOUT) {
		trapp_report_error(params, &challenge, TRAPP_ERROR_TOO_SLOW);
		return -EPERM;
	} else if (verify_result == TRAPP_RSLT_WRONG) {
		trapp_report_error(params, &challenge,
			TRAPP_ERROR_BAD_SIGNATURE);
		return -EPERM;
	} else {
		trapp_report_error(params, &challenge, TRAPP_ERROR_IO);
		return -EBADMSG;
	}
}
