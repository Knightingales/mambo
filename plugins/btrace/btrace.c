/*
  This file is part of MAMBO, a low-overhead dynamic binary modification tool:
      https://github.com/beehive-lab/mambo

  Copyright 2017 The University of Manchester

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#ifdef PLUGINS_NEW

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include "../../plugins.h"
#include "../../common.h"

#if 0
extern void mtrace_print_buf_trampoline(struct mtrace *trace);
extern void mtrace_buf_write(uintptr_t value, struct mtrace *trace);

void mtrace_print_buf(struct mtrace *mtrace_buf) {
  for (int i = 0; i < mtrace_buf->len; i++) {
    /* Warning: printing formatted strings is very slow
       For practical use, you are encouraged to process the data in memory
       or write the trace in the raw binary format */
    int size = (int)(mtrace_buf->entries[i].info >> 1);
    char *type = (mtrace_buf->entries[i].info & 1) ? "w" : "r";
    fprintf(stderr, "%s: %p\t%d\n", type, (void *)mtrace_buf->entries[i].addr, size);
  }
  mtrace_buf->len = 0;
}

#endif

static void branch_shout(void * ptr)
{
	printf("Branching to %p\n", ptr);
}

struct branch_counters
{
	uint32_t thumb_movh16;
	uint32_t thumb_pop16;
	uint32_t thumb_ldri32;
	uint32_t thumb_ldr32;
	uint32_t thumb_ldmfd32ldmea32;
	uint32_t thumb_bx16;
	uint32_t thumb_blx16;
	uint32_t thumb_bl32;
	uint32_t thumb_bl_arm32;
	uint32_t thumb_b16b32;
	uint32_t thumb_cbz16cbnz16;
	uint32_t thumb_cond16cond32;
	uint32_t thumb_tbb32tbh32;
	uint32_t thumb_other;

	uint32_t arm_b;
	uint32_t arm_blx;
	uint32_t arm_bl;
	uint32_t arm_blxi;
	uint32_t arm_bx;
	uint32_t arm_ldm;
	uint32_t arm_ldr;
	uint32_t arm_misc;
	uint32_t arm_other;

	uint32_t total;
}
branches = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void branch_count(mambo_context * ctx)
{
	branches.total++;

	if (mambo_get_inst_type(ctx) == THUMB_INST)
	{
		switch (ctx->code.inst)
		{
			case THUMB_MOVH16:
			{
				branches.thumb_movh16++;

				break;
			}

			case THUMB_POP16:
			{
				branches.thumb_pop16++;

				break;
			}

			case THUMB_LDRI32:
			{
				branches.thumb_ldri32++;

				break;
			}

			case THUMB_LDR32:
			{
				branches.thumb_ldr32++;

				break;
			}

			case THUMB_LDMFD32:
			case THUMB_LDMEA32:
			{
				branches.thumb_ldmfd32ldmea32++;

				break;
			}

			case THUMB_BX16:
			{
				branches.thumb_bx16++;

				break;
			}

			case THUMB_BLX16:
			{
				branches.thumb_blx16++;

				break;
			}

			case THUMB_BL32:
			{
				branches.thumb_bl32++;

				break;
			}

			case THUMB_BL_ARM32:
			{
				branches.thumb_bl_arm32++;

				break;
			}

			case THUMB_B16:
			case THUMB_B32:
			{
				branches.thumb_b16b32++;

				break;
			}

			case THUMB_CBZ16:
			case THUMB_CBNZ16:
			{
				branches.thumb_cbz16cbnz16++;

				break;
			}

			case THUMB_B_COND16:
			case THUMB_B_COND32:
			{
				branches.thumb_cond16cond32++;

				break;
			}

			case THUMB_TBB32:
			case THUMB_TBH32:
			{
				branches.thumb_tbb32tbh32++;

				break;
			}

			default:
			{
				branches.thumb_other++;

				break;
			}
		}
	}
	else
	{
		switch (ctx->code.inst)
		{
			case ARM_B:
			{
				branches.arm_b++;

				break;
			}

			case ARM_BLX:
			{
				branches.arm_blx++;

				break;
			}

			case ARM_BL:
			{
				branches.arm_bl++;

				break;
			}

			case ARM_BLXI:
			{
				branches.arm_blxi++;

				break;
			}

			case ARM_BX:
			{
				branches.arm_bx++;

				break;
			}

			case ARM_LDM:
			{
				branches.arm_ldm++;

				break;
			}

			case ARM_LDR:
			{
				branches.arm_ldr++;

				break;
			}

			case ARM_ADC:
			case ARM_ADD:
			case ARM_EOR:
			case ARM_MOV:
			case ARM_ORR:
			case ARM_SBC:
			case ARM_SUB:
			case ARM_RSC:
			{
				branches.arm_misc++;

				break;
			}

			default:
			{
				branches.arm_other++;

				break;
			}
		}
	}
}

#define REGISTER_BACKUP 16

uint32_t shadowstack[1024] = { 0 };
uint32_t entries = 0;
typedef struct
{
	uint32_t pc;
	uint32_t sp;
	uint32_t gprs[REGISTER_BACKUP];
	uint32_t lr;
	uint32_t arg;
	mambo_context * ctx;
} regs_t;

uint32_t interworking = 0;

extern void btrace_save_regs(mambo_context * ctx, regs_t * regs);

void stack_print(uint32_t sp_l)
{
	int i;

	for (i = 0; i < 32; ++i)
	{
		printf("[SP = 0x%x + %2d] = 0x%x\n", sp_l, (i - 8) * sizeof(uint32_t), *((uint32_t *)sp_l  - 8 + i));
	}
}

void regs_print(uint32_t regs[8])
{
	int i;

	for (i = 0; i < REGISTER_BACKUP; ++i)
		printf("r%d = 0x%x\n", i, regs[i]);
}

void btrace_error()
{
	printf("BTrace error. Exiting...\n");

	exit(1);
}

extern void btrace_branch_hook(regs_t * args);
extern void btrace_return_hook(regs_t * args);

static uint32_t returns = 0;

static uint32_t stack_pos = 0;
static uint32_t stack[2048];

int btrace_branch_hook_c(regs_t * args)
{
	mambo_context * ctx = args->ctx;
	uint32_t retpos = 0;

	int i = 0;
#ifdef DEBUG
	for (i = 0; i < stack_pos; ++i)
		printf("\t");
	printf("(%8p) CALL ", ctx->code.read_address);
#endif

	if (mambo_get_inst_type(args->ctx) == ARM_INST)
	{
#ifdef DEBUG
		printf("ARM (%d)", ctx->code.inst);
#endif
		if (ctx->code.inst == ARM_BLX)
		{
			retpos = args->pc + 4 + 1;
		}
		else
		{
			retpos = args->pc + 4 + 1;
		}
	}
	else
	{
		switch (ctx->code.inst)
		{
			case THUMB_BL32:
#ifdef DEBUG
				printf("THUMB_BL32");
#endif
				retpos = args->pc + 4 + 1;

				break;

			case THUMB_BLX16:
#ifdef DEBUG
				printf("THUMB_BLX16");
#endif
				retpos = args->pc + 2 + 1;

				break;

			case THUMB_BL_ARM32:
#ifdef DEBUG
				printf("THUMB_BL_ARM32");
#endif
				retpos = args->pc + 4 + 1;

				break;

			default:
#ifdef DEBUG
				printf("THUMB BRANCH (%d)", ctx->code.inst);
#endif
				retpos = args->pc + 2 + 1;

				break;
		}
	}

	stack[stack_pos++] = retpos;

#ifdef DEBUG
	printf("(SP = 0x%x Ret = 0x%x)\n", args->sp, stack[stack_pos - 1]);
#endif

	return 0;
}

int btrace_return_hook_c(regs_t * args)
{
	mambo_context * ctx = args->ctx;
	uint32_t retaddr;
	int i;
#ifdef DEBUG
	for (i = 0; i < stack_pos - 1; ++i)
		printf("\t");

	printf("(%8p) RET ", ctx->code.read_address);
#endif
	if (mambo_get_inst_type(args->ctx) == ARM_INST)
	{
		switch (ctx->code.inst)
		{
			case ARM_BX:
			{
#ifdef DEBUG
				printf("ARM_BX");
#endif
				retaddr = args->gprs[lr];

				break;
			}

			case ARM_LDM:
			{
				uint32_t rn, regs, prepost, updown, wb, psr, i, count, regval;

#ifdef DEBUG
				printf("ARM_LDM ");
#endif
				arm_ldm_decode_fields(ctx->code.read_address, &rn, &regs, &prepost, &updown, &wb, &psr);

				count = 0;

				for (i = 0; i < 16; ++i)
					if (regs & (1 << i))
						count++;

				count--;

				if (rn == sp)
				{
					regval = args->sp;
				}
				else
				{
					regval = args->gprs[rn];
				}

#ifdef DEBUG
				printf("SP = Rn = %u, Regs = 0x%x, prepost = %u, updown = %u, wb = %u, psr = %u\n", rn, regs, prepost, updown, wb, psr);
#endif
				retaddr = *((uint32_t *)regval + (updown ? 1 : -1) * (count - prepost));

				break;

			}
			default:
			{
#ifdef DEBUG
				printf("RUN: Unsupported ARM return (%d)!\n", ctx->code.inst);
#endif
				retaddr = 0;

				break;
			}
		}
	}
	else
	{
		uint16_t inst = *((uint16_t *)ctx->code.read_address);

		switch (ctx->code.inst)
		{
			case THUMB_POP16:
			{
#ifdef DEBUG
				printf("THUMB_POP16");
#endif
				retaddr = *((uint32_t *)((uint8_t *)args->sp + args->arg));

				break;
			}

			case THUMB_BX16:
			{
#ifdef DEBUG
				printf("THUMB_BX16 (rn = %u)", args->arg);
#endif
				retaddr = args->gprs[lr];

				break;
			}

			case THUMB_LDRI32:
			{
#ifdef DEBUG
				printf("THUMB_LDRI32");
#endif
				retaddr = *((uint32_t *)args->sp);

				break;
			}

			case THUMB_LDMFD32:
			{
				int i;
				uint32_t writeback, rn, reglist, count = 0;
				uint32_t regval;

				thumb_ldmfd32_decode_fields(ctx->code.read_address, &writeback, &rn, &reglist);

				for (i = 0; i < 16; ++i)
					if ((1 << i) & reglist)
						count++;
				count--;
#ifdef DEBUG
				printf("THUMB_LDMFD32 writeback = %u rn = %u reglist = 0x%x\n", writeback, rn, reglist);
#endif
				retaddr = *((uint32_t *)args->sp + count);

				break;
			}

			default:
			{
#ifdef DEBUG
				printf("RUN: Unsupported THUMB return (%d)!\n", ctx->code.inst);
#endif
				retaddr = 0;
			}
		}

	}

#ifdef DEBUG
		printf(" (SP = 0x%x Ret = 0x%x)\n", args->sp, retaddr);
#endif

	if ((retaddr != stack[stack_pos - 1]) && ((retaddr | 1) != stack[stack_pos - 1]))
	{
		int i;

		if ((retaddr == stack[stack_pos]) || ((retaddr | 1) == stack[stack_pos]))
		{
			stack_pos++;

			goto done;
		}

		for (i = 1; i < stack_pos - 1; ++i)
		{
			if ((retaddr == stack[stack_pos - 1 - i]) || ((retaddr | 1) == stack[stack_pos - 1 - i]))
			{
				/* printf("Unwinding the stack %d functions\n", i); */

				stack_pos -= i + 1;

				goto done;
			}
		}

		printf("%s instruction %d. Wrong return address. Expected (shadow): 0x%x Prediction (read): 0x%x (Failed %u times)\n", mambo_get_inst_type(args->ctx) == ARM_INST ? "ARM" : "THUMB", args->ctx->code.inst, stack[stack_pos], retaddr, ++returns);

		for (i = 0; i < stack_pos; ++i)
		{
			printf("[SHADOW + %i] = 0x%x\n", i, stack[stack_pos - i]);
		}

		regs_print(args->gprs);
		stack_print(args->sp);

		//if (returns == 2)
		//	exit(1);
	}

	--stack_pos;
done:

	return 0;
}

int btrace_pre_inst_handler(mambo_context *ctx)
{
	mambo_branch_type type = mambo_get_branch_type(ctx);

	if ((type & BRANCH_RETURN == 0) || (type & BRANCH_CALL == 0) || (type == BRANCH_NONE))
	{
		return 0;
	}

	mambo_context * cpy = (mambo_context *)malloc(sizeof(mambo_context));
	regs_t * regs = (regs_t *)malloc(sizeof(regs_t));
	memcpy(cpy, ctx, sizeof(mambo_context));

	/* PC is where I read from rather actial BB branch address */
	regs->pc = (uint32_t)ctx->code.read_address;
	regs->ctx = cpy;


	emit_push(ctx, 7);
	emit_set_reg_ptr(ctx, r0, regs);

	/* Get what's now is LR as any other place will ruin it. */
	emit_mov(ctx, r1, lr);
	emit_mov(ctx, r2, sp);

	if (type & BRANCH_RETURN)
	{
		uint32_t arg = 0;

		if (mambo_get_inst_type(ctx) == THUMB_INST)
		{
			uint16_t inst = *((uint16_t *)ctx->code.read_address);

			switch (ctx->code.inst)
			{
				case THUMB_POP16:
				{
					int i;

					for (i = 0; i <= 8; ++i)
					{
						if (inst & (1 << i))
							arg += sizeof(uint32_t);
					}

					arg -= sizeof(uint32_t);

					break;
				}

				case THUMB_BX16:
				{
					/* Get what's now is LR as any other place will ruin it. */
					arg = (inst >> 3) & 0xf;

					break;
				}

				case THUMB_LDRI32:
				{
					uint32_t rn, rt, imm8, p, u, w;
					thumb_ldri32_decode_fields(ctx->code.read_address, &rt, &rn, &imm8, &p, &u, &w);

					arg = imm8;

					break;
				}

				case THUMB_LDMFD32:
				{
					int i;
					uint32_t writeback, rn, reglist, count = 0;

					thumb_ldmfd32_decode_fields(ctx->code.read_address, &writeback, &rn, &reglist);

					for (i = 0; i < lr; ++i)
						count += ((1 << i) & reglist) != 0;

					arg = count * sizeof(uint32_t);

					break;
				}

				default:
				{
					printf("Not any decoded THUMB instruction (%d)\n", ctx->code.inst);

					break;
				}
			}
		}
		else
		{
			uint32_t inst = *((uint32_t *)ctx->code.read_address);

			switch (ctx->code.inst)
			{
				case ARM_BX:
				{
					arg = (inst >> 3) & 0xf;

					break;
				}

				case ARM_LDM:
				{
					break;
				}

				default:
				{
					printf("SCAN: ARM return (%d)!\n", ctx->code.inst);

					break;
				}
			}
		}

		regs->arg = arg;

		emit_safe_fcall(ctx, btrace_return_hook, 2);
	}
	else if (type & BRANCH_CALL)
	{
		emit_safe_fcall(ctx, btrace_branch_hook, 3);
	}

	emit_pop(ctx, 7);


	/* Not a branch. Ignore. */
	if (type == BRANCH_NONE)
	{
		 return 0;
	}

	return 0;
#if 0
	branch_count(ctx);

	if (type & BRANCH_INTERWORKING)
	{
		printf("INTERWORKING INST %d %s\n", ctx->code.inst, mambo_get_inst_type(ctx) == ARM_INST ? "ARM -> THUMB" : "THUMB -> ARM");
		if (++interworking == 4)
		{
			printf("QUIT INTERWORKING\n");
			while (1);
		}
	}

	emit_push(ctx, 3);
	emit_set_reg_ptr(ctx, r0, cpy);
	emit_set_reg_ptr(ctx, r1, regs);
	emit_fcall(ctx, btrace_save_regs);

	if (type & BRANCH_CALL)
	{
		emit_safe_fcall(ctx, push_shadowstack, 0);
	}
	else if (type & BRANCH_RETURN)
	{
		emit_safe_fcall(ctx, verify_shadowstack, 0);
	}

	emit_pop(ctx, 3);
#endif
	return 0;

	if (mambo_get_inst_type(ctx) == THUMB_INST)
	{
		switch (ctx->code.inst)
		{
			case THUMB_MOVH16:
			{

				break;
			}

			case THUMB_POP16:
			{

				break;
			}

			case THUMB_LDRI32:
			{

				break;
			}

			case THUMB_LDR32:
			{

				break;
			}

			case THUMB_LDMFD32:
			case THUMB_LDMEA32:
			{

				break;
			}

			case THUMB_BX16:
			{

				break;
			}

			case THUMB_BLX16:
			{

				break;
			}

			case THUMB_BL32:
			{

				break;
			}

			case THUMB_BL_ARM32:
			{
				uint32_t sign_bit;
				uint32_t offset_high;
				uint32_t j1;
				uint32_t j2;
				uint32_t offset_low;

				thumb_bl_arm32_decode_fields(ctx->code.read_address, &sign_bit, &offset_high, &j1, &j2, &offset_low);

				printf("THUMB_BL_ARM32:\n\tsign_bit: %u\n\toffset_high: %u\n\tj1: %u\n\tj2: %u\n\toffset_low: %u\n", sign_bit, offset_high, j1, j2, offset_low);

				break;
			}

			case THUMB_B16:
			case THUMB_B32:
			{

				break;
			}

			case THUMB_CBZ16:
			case THUMB_CBNZ16:
			{

				break;
			}

			case THUMB_B_COND16:
			case THUMB_B_COND32:
			{

				break;
			}

			case THUMB_TBB32:
			case THUMB_TBH32:
			{

				break;
			}

			default:
			{

				break;
			}
		}
	}
	else
	{
		if (type & BRANCH_CALL)
		{
			/* Install shadow stack */
			switch (ctx->code.inst)
			{
				case ARM_BLX:
				{
					unsigned int rn;

					printf("BLX Branch ");

					arm_blx_decode_fields(ctx->code.read_address, &rn);

					emit_mov(ctx, 0, rn);
					emit_fcall(ctx, &branch_shout);

					break;
				}

				case ARM_BL:
				{
					unsigned int offset_branch;

					printf("BL Branch ");

					arm_bl_decode_fields(ctx->code.read_address, &offset_branch);

					emit_set_reg_ptr(ctx, 0, ctx->code.read_address + offset_branch + 4);
					emit_fcall(ctx, &branch_shout);

					break;
				}

				case ARM_BLXI:
				{
					unsigned int h;
					unsigned int imm24;

					arm_blxi_decode_fields(ctx->code.read_address, &h, &imm24);

					break;
				}
			}
		}

		if (type & BRANCH_RETURN)
		{
			/* Install shadow stack check */
			switch (ctx->code.inst)
			{
				case ARM_BX:
				{
					unsigned int rn;

					arm_bx_decode_fields(ctx->code.read_address, &rn);
					break;
				}

				case ARM_LDM:
				{
					unsigned int rn, regs, p, u, w, s;

					arm_ldm_decode_fields(ctx->code.read_address, &rn, &regs, &p, &u, &w, &s);
					break;
				}

				case ARM_LDR:
				{
					unsigned int i, rd, rn, op2, p, u, w;

					arm_ldr_decode_fields(ctx->code.read_address, &i, &rd, &rn, &op2, &p, &u, &w);
					break;
				}
			}
		}

		if (type & BRANCH_INDIRECT)
		{
			/* Install branch target validation */
			switch (ctx->code.inst)
			{
				case ARM_ADC:
				case ARM_ADD:
				case ARM_EOR:
				case ARM_MOV:
				case ARM_ORR:
				case ARM_SBC:
				case ARM_SUB:
				case ARM_RSC:
				{
					unsigned int immediate, opcode, set_flags, rd, rn, operand2, rm = reg_invalid;

					arm_data_proc_decode_fields(ctx->code.read_address, &immediate, &opcode, &set_flags, &rd, &rn, &operand2);

					break;
				}

				case ARM_BX:
				{
					unsigned int rn;

					arm_bx_decode_fields(ctx->code.read_address, &rn);

					break;
				}

				case ARM_LDM:
				{
					unsigned int rn, regs, p, u, w, s;

					arm_ldm_decode_fields(ctx->code.read_address, &rn, &regs, &p, &u, &w, &s);

					break;
				}

				case ARM_LDR:
				{
					unsigned int i, rd, rn, op2, p, u, w;

					arm_ldr_decode_fields(ctx->code.read_address, &i, &rd, &rn, &op2, &p, &u, &w);

					break;
				}

				case ARM_BLX:
				{
					unsigned int rn;

					arm_blx_decode_fields(ctx->code.read_address, &rn);
					break;
				}
			}
		}
	}
	return 0;

#if 0
	/* Example function call emit */
	emit_push(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << lr));

	uintptr_t info = (size << 1) | (is_store ? 1 : 0);
	emit_set_reg(ctx, 1, info);
	emit_set_reg_ptr(ctx, 2, &mtrace_buf->entries);
	emit_fcall(ctx, mtrace_buf_write);

	emit_pop(ctx, (1 << 0) | (1 << 1) | (1 << 2) | (1 << lr));
	/* Example end */
#endif
}

/*
int mtrace_pre_thread_handler(mambo_context *ctx) {
  struct mtrace *mtrace_buf = mambo_alloc(ctx, sizeof(*mtrace_buf));
  assert(mtrace_buf != NULL);
  mtrace_buf->len = 0;

  int ret = mambo_set_thread_plugin_data(ctx, mtrace_buf);
  assert(ret == MAMBO_SUCCESS);
}
*/

int mtrace_post_thread_handler(mambo_context *ctx)
{
#if DIAG_COUNTERS
	uint32_t thumb_movh16;
	uint32_t thumb_pop16;
	uint32_t thumb_ldri32;
	uint32_t thumb_ldr32;
	uint32_t thumb_ldmfd32ldmea32;
	uint32_t thumb_bx16;
	uint32_t thumb_blx16;
	uint32_t thumb_bl32;
	uint32_t thumb_bl_arm32;
	uint32_t thumb_b16b32;
	uint32_t thumb_cbz16cbnz16;
	uint32_t thumb_cond16cond32;
	uint32_t thumb_tbb32tbh32;

	uint32_t arm_b;
	uint32_t arm_blx;

	printf("THUMB MOVH16: %u\n", branches.thumb_movh16);
	printf("THUMB POP16: %u\n", branches.thumb_pop16);
	printf("THUMB LDRI32: %u\n", branches.thumb_ldri32);
	printf("THUMB LDR32: %u\n", branches.thumb_ldr32);
	printf("THUMB LDMFD32/LDMEA32: %u\n", branches.thumb_ldmfd32ldmea32);
	printf("THUMB BX16: %u\n", branches.thumb_bx16);
	printf("THUMB BLX16: %u\n", branches.thumb_blx16);
	printf("THUMB BL32: %u\n", branches.thumb_bl32);
	printf("THUMB BL_ARM32: %u\n", branches.thumb_bl_arm32);
	printf("THUMB B16/B32: %u\n", branches.thumb_b16b32);
	printf("THUMB CBZ16/CBNZ16: %u\n", branches.thumb_cbz16cbnz16);
	printf("THUMB COND16/COND32: %u\n", branches.thumb_cond16cond32);
	printf("THUMB TBB32/TBH32: %u\n", branches.thumb_tbb32tbh32);
	printf("THUMB Other: %u\n", branches.thumb_other);

	printf("ARM B: %u\n", branches.arm_b);
	printf("ARM BLX: %u\n", branches.arm_blx);
	printf("ARM BL: %u\n", branches.arm_bl);
	printf("ARM BLXi: %u\n", branches.arm_blxi);
	printf("ARM BX: %u\n", branches.arm_bx);
	printf("ARM LDM: %u\n", branches.arm_ldm);
	printf("ARM LDR: %u\n", branches.arm_ldr);
	printf("ARM Misc: %u\n", branches.arm_misc);
	printf("ARM Other: %u\n", branches.arm_other);
	printf("ARM Total: %u\n", branches.total);
#endif
}

__attribute__((constructor)) void btrace_init_plugin() {
  mambo_context *ctx = mambo_register_plugin();
  assert(ctx != NULL);

/*
  mambo_register_pre_thread_cb(ctx, &mtrace_pre_thread_handler);
*/

  mambo_register_post_thread_cb(ctx, &mtrace_post_thread_handler);

  mambo_register_pre_inst_cb(ctx, &btrace_pre_inst_handler);
}
#endif
