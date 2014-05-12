/* checkfn_c.h
 *  by Alex Chadwick
 *
 * Implementation in C of the core checking function.
 */

#ifndef CHECKFN_C_H
#define CHECKFN_C_H

#include <linux/types.h>
#include <stddef.h>

/* range of memory
 * Represents a range of simulated memory with a size and address in the simulated
 * address space, as well as a pointer to the 'real' data.
 */
struct range {
	const uint32_t * restrict data;
	uint32_t address;
	size_t size;
};

/* core checking function
 * Simulates the behaviour of the core checking function with specified parameters.
 * y is the number of iterations.
 * C is a pointer to the seed.
 * regions is an array of size region_count of {simulated} regions to hash.
 * lr is the link register at the time of the call to checkfn.
 * checksum is the region of memory of the ASM checksum function itself.
 */
void checkfn_c(
	uint32_t y,
	uint32_t * restrict C,
	const struct range * restrict regions,
	uint32_t region_count,
	uint32_t lr,
	const struct range checksum);

#endif /* CHECKFN_C_H */
