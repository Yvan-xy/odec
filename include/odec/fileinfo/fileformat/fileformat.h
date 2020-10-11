//
// Created by dyf on 2020/10/11.
//

#ifndef ODEC_FILEFORMAT_H
#define ODEC_FILEFORMAT_H

#include <string>
#include <vector>

#include "llvm/Object/ELF.h"
#include "odec/fileinfo/ftypes.h"

namespace odec::fileinfo {

    class FileFormat {
    protected:
        std::string crc32;
        std::string md5;
        std::string sha256;
        std::string sectionCrc32;
        std::string sectionMd5;
        std::string sectionSha256;

    public:
        std::size_t getLoadedFileLength() const;

        const unsigned char *getLoadedBytesData() const;

        LoadFlags getLoadFlags() const;

    };

}  // namespace odec

#endif  // ODEC_FILEFORMAT_H
