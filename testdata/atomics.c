/* Exercises the atomic operations supported by the kernel. Each program returns
 * the line number of the first failed check, or 0 if all checks passed.
 *
 * Requires -mcpu=v4 for load-acquire and store-release instructions. */

#include "common.h"

char __license[] __section("license") = "MIT";

#define check(cond) \
	if (!(cond)) \
		return __LINE__;

/* The library distinguishes atomics by the operation encoded in the immediate,
 * the operand size is shared with regular loads and stores.
 *
 * All read-modify-write ops are therefore only exercised as 64-bit, with a
 * single 32-bit case to cover that size. Load-acquire and store-release are the
 * only ops valid for 8 and 16-bit operands, so those cover all sizes. */
__section("socket") int atomics() {
	volatile uint64_t u64;
	volatile uint32_t u32;

	u64 = 0;
	__atomic_fetch_add(&u64, 2, __ATOMIC_RELAXED);
	check(u64 == 2);
	check(__sync_fetch_and_add(&u64, 3) == 2);
	check(u64 == 5);

	u32 = 0;
	__atomic_fetch_add(&u32, 2, __ATOMIC_RELAXED);
	check(u32 == 2);
	check(__sync_fetch_and_add(&u32, 3) == 2);
	check(u32 == 5);

	u64 = 0b111;
	__atomic_fetch_and(&u64, 0b011, __ATOMIC_RELAXED);
	check(u64 == 0b011);
	check(__sync_fetch_and_and(&u64, 0b010) == 0b011);
	check(u64 == 0b010);

	u64 = 0b001;
	__atomic_fetch_or(&u64, 0b010, __ATOMIC_RELAXED);
	check(u64 == 0b011);
	check(__sync_fetch_and_or(&u64, 0b100) == 0b011);
	check(u64 == 0b111);

	u64 = 0b011;
	__atomic_fetch_xor(&u64, 0b110, __ATOMIC_RELAXED);
	check(u64 == 0b101);
	check(__sync_fetch_and_xor(&u64, 0b011) == 0b101);
	check(u64 == 0b110);

	u64 = 1;
	check(__sync_lock_test_and_set(&u64, 2) == 1);
	check(u64 == 2);

	u64 = 1;
	check(__sync_val_compare_and_swap(&u64, 0, 2) == 1);
	check(u64 == 1);
	check(__sync_val_compare_and_swap(&u64, 1, 2) == 1);
	check(u64 == 2);

	return 0;
}

__section("socket") int atomics_acq_rel() {
	volatile uint64_t u64;
	volatile uint32_t u32;
	volatile uint16_t u16;
	volatile uint8_t u8;

	u64 = 1;
	check(__atomic_load_n(&u64, __ATOMIC_ACQUIRE) == 1);
	__atomic_store_n(&u64, 2, __ATOMIC_RELEASE);
	check(u64 == 2);

	u32 = 1;
	check(__atomic_load_n(&u32, __ATOMIC_ACQUIRE) == 1);
	__atomic_store_n(&u32, 2, __ATOMIC_RELEASE);
	check(u32 == 2);

	u16 = 1;
	check(__atomic_load_n(&u16, __ATOMIC_ACQUIRE) == 1);
	__atomic_store_n(&u16, 2, __ATOMIC_RELEASE);
	check(u16 == 2);

	u8 = 1;
	check(__atomic_load_n(&u8, __ATOMIC_ACQUIRE) == 1);
	__atomic_store_n(&u8, 2, __ATOMIC_RELEASE);
	check(u8 == 2);

	return 0;
}
