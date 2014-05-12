/* checkfn_c.c
 *  by Alex Chadwick
 *
 * Implementation in C of the core checking function.
 */

#include "checkfn_c.h"

#include <linux/kernel.h>
#include <linux/types.h>
#include <stddef.h>

/* rotate left bits
 * Rotates the bit pattern of reg left by amt.
 */
static inline uint32_t rotl(uint32_t reg, uint32_t amt) {
	return reg << amt | (reg >> (32 - amt));
}
/* rotate right bits
 * Rotates the bit pattern of reg right by amt.
 */
static inline uint32_t rotr(uint32_t reg, uint32_t amt) {
	return rotl(reg, 32 - amt);
}
/* load register
 * Mimics the behaviour of the ARM ldr instruction on a simulated memory.
 */
static inline uint32_t ldr(uint32_t addr, struct range mem) {
	return rotr(mem.data[(addr - mem.address) >> 2], ((addr - mem.address) & 3) * 8);
}

void checkfn_c(
	uint32_t y,
	uint32_t * restrict C,
	const struct range * restrict regions,
	uint32_t region_count,
	uint32_t lr,
	const struct range checksum)
{
	#define Cj(n) C[(j - n) & 7]
	uint32_t i, j, x, s, d, val, e, log2sz;
	const struct range *range;

	s = 0x000000d3;
	j = 0;
	x = lr;
	//lr = (checksum.address + 0x400 + (((Cj(0) >> 4) & 3) << 7));
	range = &checksum;
	do {
		e = 0;
		lr = checksum.address + 0x478;
		for (log2sz = 0; 1 << log2sz < range->size; log2sz++);
		for (i = 8 * y; i >= 1; --i) {
			switch ((Cj(0) >> 4) & 3) {
			case 0:
				x = (x + (x | 5) * (x | 5));
				s &= ~0xc0000000;
				s |= (x & 0x80000000);
				s |= x == 0 ? 0x40000000 : 0;
				x = x ^ rotl(Cj(0), 4);
				d = range->address + (x >> (32 - log2sz));
                                val = ldr(d, *range);
				Cj(0) = (rotr(Cj(1), 2)  ^ Cj(7)) + e;
				Cj(1) = (rotr(lr, 4)     ^ Cj(0)) + Cj(2);
				Cj(2) = (rotr(Cj(3), 6)  ^ Cj(1)) + d;
				Cj(3) = (rotr(Cj(4), 8)  ^ Cj(2)) + (checksum.address + 0x43c);
				Cj(4) = (rotr(s, 10)     ^ Cj(3)) + Cj(5);
				Cj(5) = (rotr(Cj(6), 12) ^ Cj(4)) + val;
				Cj(6) = (rotr(Cj(2), 14) ^ Cj(5)) + Cj(7);
				Cj(7) = (rotr(i, 16)     ^ Cj(6)) + Cj(0);
				Cj(0) = (Cj(0) ^ lr) + val;
				e = ldr(checksum.address + 0x478 + (((int32_t)x) >> 22), checksum);
				lr = (checksum.address + 0x478);
				break;
			case 1:
				x = (x + (x | 5) * (x | 5));
				s &= ~0xc0000000;
				s |= (x & 0x80000000);
				s |= x == 0 ? 0x40000000 : 0;
				x = x ^ rotl(Cj(3), 8);
				d = range->address + (x >> (32 - log2sz));
                                val = ldr(d, *range);
				Cj(4) = (rotr(lr, 18)    ^ Cj(3)) + e;
				Cj(5) = (rotr(Cj(6), 20) ^ Cj(4)) + d;
				Cj(6) = (rotr(Cj(2), 22) ^ Cj(5)) + Cj(7);
				Cj(7) = (rotr(s, 24)     ^ Cj(6)) + Cj(0);
				Cj(0) = (rotr(Cj(1), 26) ^ Cj(7)) + Cj(6);
				Cj(1) = (rotr(i, 28)     ^ Cj(0)) + Cj(2);
				Cj(2) = (rotr(Cj(3), 30) ^ Cj(1)) + val;
				Cj(3) = (rotr(Cj(4), 4)  ^ Cj(2)) + (checksum.address + 0x4f8);
				Cj(2) = (Cj(2) ^ lr) + val;
				e = ldr(checksum.address + 0x500 + (((int32_t)x) >> 22), checksum);
				lr = (checksum.address + 0x500);
				break;
			case 2:
				x = (x + (x | 5) * (x | 5));
				s &= ~0xc0000000;
				s |= (x & 0x80000000);
				s |= x == 0 ? 0x40000000 : 0;
				x = x ^ (rotl(Cj(4), 12));
				d = range->address + (x >> (32 - log2sz));
                                val = ldr(d, *range);
				Cj(6) = (rotr(Cj(2), 8)  ^ Cj(5)) + e;
				Cj(7) = (rotr(lr, 12)    ^ Cj(6)) + Cj(0);
				Cj(4) = (rotr(d, 16)     ^ Cj(3)) + Cj(5);
				Cj(5) = (rotr(Cj(6), 20) ^ Cj(4)) + s;
				Cj(2) = (rotr(Cj(3), 24) ^ Cj(1)) + val;
				Cj(3) = (rotr(Cj(4), 28) ^ Cj(2)) + (checksum.address + 0x55c);
				Cj(0) = (rotr(Cj(1), 2)  ^ Cj(7)) + Cj(6);
				Cj(1) = (rotr(i, 6)      ^ Cj(0)) + Cj(2);
				Cj(1) = (Cj(1) ^ lr) + val;
				e = ldr(checksum.address + 0x588 + (((int32_t)x) >> 22), checksum);
				lr = (checksum.address + 0x588);
				break;
			default:
				x = (x + (x | 5) * (x | 5));
				s &= ~0xc0000000;
				s |= (x & 0x80000000);
				s |= x == 0 ? 0x40000000 : 0;
				x = x ^ rotl(Cj(6), 16);
				d = range->address + (x >> (32 - log2sz));
                                val = ldr(d, *range);
				Cj(7) = (rotr(Cj(6), 10) ^ lr)    + e;
				Cj(6) = (rotr(Cj(5), 14) ^ Cj(2)) + Cj(7);
				Cj(5) = (rotr(Cj(4), 18) ^ Cj(6)) + d;
				Cj(4) = (rotr(Cj(3), 22) ^ i)     + Cj(5);
				Cj(3) = (rotr(Cj(2), 26) ^ Cj(4)) + (checksum.address + 0x5d8);
				Cj(2) = (rotr(Cj(1), 30) ^ Cj(3)) + val;
				Cj(1) = (rotr(Cj(0), 8)  ^ Cj(2)) + s;
				Cj(0) = (rotr(Cj(7), 16) ^ Cj(6)) + Cj(1);
				Cj(7) = (Cj(7) ^ lr) + val;
				e = ldr(checksum.address + 0x610 + (((int32_t)x) >> 21), checksum);
				lr = (checksum.address + 0x610);
				break;
			}
			j = (j + 1) % 8;
			s |= 0x20000000; // carry bit from --i
		}
		range = regions++;
	} while (region_count--);
	#undef Cj
}
