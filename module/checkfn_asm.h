/* checkfn_asm.h
 *  by Alex Chadwick
 *
 * Implementation in ARM assembly of the core checking function.
 */

#ifndef CHECKFN_ASM_H
#define CHECKFN_ASM_H

#include <linux/types.h>
#include <stddef.h>

/* region of memory
 * Represents a region of memory hashed by the checking function.
 */
struct range_asm {
	const void * restrict data;
	uint32_t log2size; // 32 - log_2(size) of region in bytes
};

/* core checking function
 * Assembly code core checking function.
 * y number of iterations.
 * C seed value.
 * regions an array of region_count range_asm structures containing regions
 *         to be included in the hash.
 * NOTE: the result of this function is affected by the machine state
 *       including lr and cpsr.
 */
void checkfn_asm(
	uint32_t y,
	uint32_t * restrict C,
	const struct range_asm * restrict regions,
	uint32_t region_count);

/* core checking function's body
 * A pointer to the start and end of the inner loop of the core checking function.
 */
extern const uint32_t checkfn_asm_body[];
extern const uint32_t checkfn_asm_body_end[];

#endif /* CHECKFN_ASM_H */
