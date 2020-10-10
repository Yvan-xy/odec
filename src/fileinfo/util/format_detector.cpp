//
// Created by dyf on 2020/10/10.
//

#include <map>
#include <cmath>
#include <fstream>
#include <iostream>
#include <streambuf>

#include "odec/utils/string.h"
#include "odec/fileinfo/util/format_detector.h"

using namespace odec::utils;

namespace odec {
namespace fileinfo {

const std::size_t COFF_FILE_HEADER_BYTE_SIZE = 20;

const std::map<std::pair<std::size_t, std::string>, Format> magicFormatMap = {
        // PE
        {{0, "MZ"}, Format::PE},
        {{0, "ZM"}, Format::PE},

        // COFF - only Little endian variants.
        // See PELIB_IMAGE_FILE_MACHINE.
        {{0, "\x4c""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_I386
        {{0, "\x4d""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_I486
        {{0, "\x4e""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_PENTIUM
        {{0, "\x84""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_ALPHA
        {{0, "\xa2""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_SH3
        {{0, "\xa3""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_SH3DSP
        {{0, "\xa4""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_SH3E
        {{0, "\xa6""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_SH4
        {{0, "\xa8""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_SH5

        {{0, "\xc0""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_ARM
        {{0, "\xc2""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_THUMB
        {{0, "\xc4""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_ARMNT
        {{0, "\xd3""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_AM33
        {{0, "\xf0""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_POWERPC

        {{0, std::string("\x00\x02", 2)}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_POWERPCFP

        {{0, "\xc4""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_IA64
        {{0, "\x68""\x02"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_MOTOROLA68000
        {{0, "\x90""\x02"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_PARISC
        {{0, "\x84""\x02"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_ALPHA64

        // https://opensource.apple.com/source/file/file-23/file/magic/Magdir/mips.auto.html
        {{0, "\x60""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_R3000_BIG, MIPSEB-LE ECOFF executable
        {{0, "\x62""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_R3000_LITTLE, MIPSEL ECOFF executable
        {{0, "\x63""\x01"}, Format::COFF}, // MIPSEB-LE MIPS-II ECOFF executable
        {{0, "\x66""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_R4000, MIPSEL MIPS-II ECOFF executable
        {{0, "\x40""\x01"}, Format::COFF}, // MIPSEB-LE MIPS-III ECOFF executable
        {{0, "\x42""\x01"}, Format::COFF}, // MIPSEL MIPS-III ECOFF executable
        {{0, "\x66""\x02"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_MIPS16
        {{0, "\x68""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_R10000
        {{0, "\x69""\x01"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_WCEMIPSV2
        {{0, "\x66""\x03"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_MIPSFPU
        {{0, "\x66""\x04"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_MIPSFPU16
        {{0, "\x20""\x05"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_TRICORE
        {{0, "\xbc""\x0e"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_EBC
        {{0, "\x64""\x86"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_AMD64
        {{0, "\x41""\x90"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_M32R
        {{0, "\x64""\xaa"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_ARM64
        {{0, "\xee""\xc0"}, Format::COFF}, // PELIB_IMAGE_FILE_MACHINE_MSIL
        // COFF - big endian magic
        // Big endian COFFs should start with 0000ffff but this long magic should
        // be enough.
        // See LLVM's COFF.h BigObjMagic
        {{0xc, "\xc7\xa1\xba\xd1\xee\xba\xa9\x4b\xaf\x20\xfa\xf6\x6a\xa4\xdc\xb8"}, Format::COFF},

        // ELF
        {{0, "\x7F""ELF"}, Format::ELF},
        // Intel-Hex
        {{0, ":"}, Format::INTEL_HEX},
        // Mach-O
        {{0, "\xFE""\xED""\xFA""\xCE"}, Format::MACHO}, // Mach-O
        {{0, "\xFE""\xED""\xFA""\xCF"}, Format::MACHO}, // Mach-O
        {{0, "\xCE""\xFA""\xED""\xFE"}, Format::MACHO}, // Mach-O
        {{0, "\xCF""\xFA""\xED""\xFE"}, Format::MACHO}, // Mach-O
        {{0, "\xCA""\xFE""\xBA""\xBE"}, Format::MACHO}  // Mach-O fat binary
    };

const std::map<std::pair<std::size_t, std::string>, Format> unknownFormatMap = {
        {{0, "\x7""\x1""\x64""\x00"}, Format::UNKNOWN}, // a.out
        {{0, "PS-X EXE"}, Format::UNKNOWN}, // PS-X
        {{257, "ustar"}, Format::UNKNOWN} // tar
};

void resetStream(std::istream& stream) {
    stream.clear();
    stream.seekg(0, std::ios::beg);
}

std::uint64_t streamSize(std::istream& stream) {
    stream.seekg(0, std::ios::end);
    std::uint64_t result = stream.tellg();
    resetStream(stream);
    return result;
}

/**
 * Check if file is strange format with Mach-O magic.
 * @param stream Input stream
 * @return @c true if input file is likely not Mach-O, @c false otherwise
 */
bool isStrangeFeedface(std::istream& stream) {
    resetStream(stream);

    if (!stream) {
        return false;
    }

    std::uint32_t ints[4];
    stream.read(reinterpret_cast<char*>(&ints), 16);

    if (ints[0] == 0xfeedface && ints[1] == 0x10 && ints[2] == 0x02) {
        return ints[3] > 0x10;
    }
    return false;
}

/**
 * Check if file is Java class
 * @param stream Input stream
 * @return @c true if input file is Java class file, @c false otherwise
 */
bool isJava(std::istream& stream) {
    resetStream(stream);

    if (!stream) {
        return false;
    }

    std::uint32_t magic = 0;
    stream.read(reinterpret_cast<char*>(&magic), 4);

    // Same for both Java and fat Mach-O
    if (magic == 0xcafebabe || magic == 0xbebafeca) {
        std::uint32_t fatCount = 0;
        stream.read(reinterpret_cast<char*>(&fatCount), 4);

        // Mach-O currently supports up to 18 architectures
        // Java version starts at 39. However file utility uses value 30
        return fatCount > 30;
    }

    return false;
}


/**
 * Detects file format of input file
 * @param filePath Path to input file
 * @param isRaw Is the input is a raw binary?
 * @return Detected file format in enumeration representation
 */
Format detectFileFormat(const std::string &filePath, bool isRaw) {
    std::ifstream stream(filePath, std::ios::in | std::ios::binary);
    if (!stream.is_open()) {
        return Format::UNDETECTABLE;
    }

    return detectFileFormat(stream, isRaw);
}

Format detectFileFormat(std::istream& inputStream, bool isRaw) {
    if (isRaw) {
        return Format::RAW_DATA;
    }

    // Check unknown formats.
    resetStream(inputStream);
    std::size_t magicSize = 0;
    for (const auto &item : unknownFormatMap) {
        magicSize = std::max(magicSize, item.first.second.length());
    }

    // Read the magic number and compare
    std::string magicNumber;
    try {
        magicNumber.resize(magicSize);
        inputStream.read(&magicNumber[0], magicSize);
        for (const auto &item : unknownFormatMap){
            if (hasSubstringOnPosition(magicNumber, item.first.second, item.first.first)) {
                return Format::UNKNOWN;
            }
        }
    } catch (...) {
        // nothing
    }

    // Check unknown format
    magicNumber = "";
    resetStream(inputStream);
    for (const auto &item : magicFormatMap) {
        magicSize = std::max(magicSize, item.first.second.length());
    }

    try {
        magicNumber.resize(magicSize);
        inputStream.read(&magicNumber[0], magicSize);
    } catch (...) {
        return Format::UNDETECTABLE;
    }

    for (const auto &item : magicFormatMap) {
        if (hasSubstringOnPosition(magicNumber, item.first.second, item.first.first)) {
            switch (item.second) {
                case Format::PE:
                    // not support yet
                    return item.second;
                case Format::COFF: {
                    if (streamSize(inputStream) < COFF_FILE_HEADER_BYTE_SIZE) {
                        return Format::UNKNOWN;
                    }
                    return Format::COFF;
                }

                case Format::MACHO: {
                    if (isStrangeFeedface(inputStream) || isJava(inputStream)) {
                        return Format::UNKNOWN;
                    }
                    return item.second;
                }
                default:
                    return item.second;
            }
        }
    }
    return Format::UNKNOWN;
}

std::string format2String(Format format) {
    switch (format) {
        case Format::UNDETECTABLE:
            return std::string("UNDETECTABLE");
        case Format::UNKNOWN:
            return std::string("UNKNOWN");
        case Format::PE:
            return std::string("PE");
        case Format::ELF:
            return std::string("ELF");
        case Format::COFF:
            return std::string("COFF");
        case Format::MACHO:
            return std::string("MACHO");
        case Format::INTEL_HEX:
            return std::string("INTEL_HEX");
        case Format::RAW_DATA:
            return std::string("RAW_DATA");
    }
}




}  // namespace fileinfo
}  // namespace odec