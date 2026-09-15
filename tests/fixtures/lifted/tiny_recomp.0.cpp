// Synthetic RexGlue-style lifted output, shaped like the real generator.
#include "ppc_context.h"

DEFINE_REX_FUNC(sub_82B10000) {
	REX_FUNC_PROLOGUE();
	uint32_t ea{};
	// mflr r12
	ctx.r12.u64 = ctx.lr;
	// bl 0x82f52114
	ctx.lr = 0x82B10008;
	__savegprlr_27(ctx, base);
	// lis r10,-32237
	ctx.r10.s64 = -2112684032;
	// addi r10,r10,-24320
	ctx.r10.s64 = ctx.r10.s64 + -24320;
	// lwz r9,0(r3)
	ctx.r9.u64 = REX_LOAD_U32(ctx.r3.u32 + 0);
	// bl 0x82b10100
	ctx.lr = 0x82B10020;
	sub_82B10100(ctx, base);
	// stw r9,8(r3)
	REX_STORE_U32(ctx.r3.u32 + 8, ctx.r9.u32);
	// blr
	return;
}

DEFINE_REX_FUNC(sub_82B10100) {
	REX_FUNC_PROLOGUE();
	// bl 0x82f60000
	ctx.lr = 0x82B10104;
	__imp__RtlEnterCriticalSection(ctx, base);
loc_82B10108:
	// lvx128 v1,r3,r4
	ctx.v1 = simde_mm_load_si128(...);
	// vmaddfp128 v2,v1,v1,v3
	ctx.v2 = simde_mm_fmadd_ps(...);
	// stvx128 v2,r5,r6
	simde_mm_store_si128(...);
	// mftb r11
	ctx.r11.u64 = REX_QUERY_TIMEBASE();
	// blr
	return;
}

DEFINE_REX_FUNC(sub_82B10200) {
	REX_FUNC_PROLOGUE();
	// lis r9,-32255
	ctx.r9.s64 = -2113732608;
	// lfs f13,18868(r9)
	ctx.f13.f64 = REX_LOAD_F32(ctx.r9.u32 + 18868);
	// bctrl
	REX_CALL_INDIRECT_FUNC(ctx.ctr.u32);
	// blr
	return;
}

DEFINE_REX_FUNC(sub_82B10300) {
	REX_FUNC_PROLOGUE();
	// lwz r11,0(r3)
	ctx.r11.u64 = REX_LOAD_U32(ctx.r3.u32 + 0);
	// stw r11,24(r4)
	REX_STORE_U32(ctx.r4.u32 + 24, ctx.r11.u32);
	// blr
	return;
}
