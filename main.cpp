#include <cstdio>
#include <cinttypes>

#include <capstone/capstone.h>

#define CODE "\x05\x34\x12\x00\x00\x74\xf9"

int main(void)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
        return -1;

//    cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);  // 以AT&T语法显示
    count = cs_disasm(handle, reinterpret_cast<const uint8_t *>(CODE), sizeof(CODE) - 1, 0x1000, 0, &insn);
    if (count > 0) {
        size_t j;
        for (j = 0; j < count; j++) {
            printf("0x%" PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                   insn[j].op_str);
        }

        cs_free(insn, count);
    } else
        printf("ERROR: Failed to disassemble given code!\n");

    cs_close(&handle);

    return 0;
}