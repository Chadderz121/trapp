/* trapp.h
 *  by Alex Chadwick.
 *
 * User land header for /dev/trapp network security module.
 */

#ifndef TRAPP_H_
#define TRAPP_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define TRAPP_FS "/dev/trapp"
#define TRAPP_DEV_NAME "trapp"

/* Status of a trapp request. */
enum trapp_status_t {
	/* Request not yet processed. */
	TRAPP_STATUS_NONE,
	/* Communicating with challenger/challengee. */
	TRAPP_STATUS_HANDSHAKE,
	/* Challenger has sent challenge. */
	TRAPP_STATUS_CHALLENGE_SENT,
	/* Challenger has received response. */
	TRAPP_STATUS_VERIFYING_RESPONSE,
	/* Challenger trusts challengee. */
	TRAPP_STATUS_VERIFIED,
	/* Error while verifying, see TRAPP_ERROR_* for details. */
	TRAPP_STATUS_ERROR
};

/* Error that occurred in a trapp request. */
enum trapp_error_t {
	/* No error occured. */
	TRAPP_ERROR_NONE,
	/* Invalid arguments to request. */
	TRAPP_ERROR_ARG,
	/* Some form of IO error occurred preventing verification. */
	TRAPP_ERROR_IO,
	/* Signature was rejected by the challenger. */
	TRAPP_ERROR_BAD_SIGNATURE,
	/* Response took too long to reach challenger. */
	TRAPP_ERROR_TOO_SLOW
};

/* Sturcture describing a trapp request. */
struct trapp_challenge_t {
	/* IN */
	/* Socket to communicate on. */
	int socket_fd;
	/* Address to talk to. */
	void *socket_addr;
	int socket_addr_len;
	/* Application information to match on for verification. */
	uint32_t application;
	uint32_t application_version;

	/* OUT */
	/* Request status. */
	enum trapp_status_t status;
	/* Request error. */
	enum trapp_error_t error;
	/* Total number of attempts (including the current one). */
	unsigned int attempt_count;
	/* Duration of the successful verification in nanoseconds (if any)
         * or 0. */
	unsigned long long duration;
};

/* Send a trapp challenge to the specified socket. */
#define IOCTL_SEND_CHALLENGE _IOWR('$', 0xf0, struct trapp_challenge_t)
/* Receive a trapp challenge from the specified socket. */
#define IOCTL_RECV_CHALLENGE _IOWR('$', 0xf1, struct trapp_challenge_t)

/* Packet sequence.
 * Challenger -- Challengee
 *        -- HELO -->
 *       <-- HELO --
 *        -- TEST -->
 *       <-- ANSR --
 *        -- RSLT -->
 */

#define TRAPP_PACKET_HELO ((uint32_t)0x48454c4f)
#define TRAPP_PACKET_TEST ((uint32_t)0x54455354)
#define TRAPP_PACKET_ANSR ((uint32_t)0x414e5352)
#define TRAPP_PACKET_RSLT ((uint32_t)0x52534c54)

#define TRAPP_HELO_SYSTEM_RPI ((uint32_t)0x52506900)

#define TRAPP_HELO_VERSION_0_0_0 ((uint32_t)0)
#define TRAPP_HELO_VERSION_CURRENT TRAPP_HELO_VERSION_0_0_0

#define TRAPP_HELO_ROLE_CHALLENGER ((uint32_t)0x56455249)
#define TRAPP_HELO_ROLE_CHALLENGEE ((uint32_t)0x4f4b0000)

#define TRAPP_RSLT_TRUSTED ((uint32_t)0x54525354)
#define TRAPP_RSLT_TIMEOUT ((uint32_t)0x534c4f57)
#define TRAPP_RSLT_WRONG ((uint32_t)0x4641494c)

/* Structures representing all trapp network traffic. */
struct trapp_packet_header_t {
	uint32_t magic;
	uint32_t length;
};
struct trapp_packet_helo_t {
	uint32_t system;
	uint32_t version;
	uint32_t application;
	uint32_t application_version;
	uint32_t role;
};
struct trapp_packet_test_t {
	uint32_t iterations;
	uint32_t seed[8];
};
struct trapp_packet_ansr_t {
	uint32_t hash[8];
	uint32_t addr_count;
	uint32_t addrs[];
};
struct trapp_packet_rslt_t {
	uint64_t duration;
	uint32_t result;
};
struct trapp_packet_t {
	struct trapp_packet_header_t header;
	union {
		struct trapp_packet_helo_t helo;
		struct trapp_packet_test_t test;
		struct trapp_packet_ansr_t ansr;
		struct trapp_packet_rslt_t rslt;
	} body;
};

#define TRAPP_PACKET_LENGTH(type) ((sizeof(struct trapp_packet_header_t)) + \
	sizeof(struct trapp_packet_ ## type ## _t))

#endif /* TRAPP_H_ */
