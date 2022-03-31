/* test1.c */

#include <stdio.h>
#include <inttypes.h>

#include <capstone/capstone.h>

// little endian (same memory order printed by GDB)
//#define CODE "\x33\x07\xa6\x00"
#define CODE "\x4d\x5a\x6f\x10\xf0\x7f"  

int main(void)
{
	csh handle;
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC, &handle) != CS_ERR_OK)
		return -1;
	count = cs_disasm(handle, (unsigned char *)CODE, sizeof(CODE)-1, 0x1000, 0, &insn);
	if (count > 0) {
		size_t j;
		for (j = 0; j < count; j++) {
			printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
					insn[j].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&handle);

    return 0;
}
