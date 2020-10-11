//
// Created by dyf on 2020/10/10.
//

#ifndef ODEC_FTYPES_H
#define ODEC_FTYPES_H

namespace odec::fileinfo {
/**
 * Supported file-format types
 */
    enum class Format {
        UNDETECTABLE,
        UNKNOWN,
        PE,
        ELF,
        COFF,
        MACHO,
        INTEL_HEX,
        RAW_DATA
    };

/**
 * Supported architectures
 */
    enum class Architecture {
        UNKNOWN, X86, X86_64, ARM, POWERPC, MIPS
    };

    enum LoadFlags {
        NONE = 0,
        NO_FILE_HASHES = 1,
        NO_VERBOSE_HASHES = 2,
        DETECT_STRINGS = 4
    };

}  // namespace odec

#endif  // ODEC_FTYPES_H
