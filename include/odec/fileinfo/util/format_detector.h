//
// Created by dyf on 2020/10/10.
//

#ifndef ODEC_FILE_DETECTOR_H
#define ODEC_FILE_DETECTOR_H

#include <string>

#include "odec/fileinfo/ftypes.h"

namespace odec::fileinfo {

    Format detectFileFormat(const std::string &filePath, bool isRaw = false);

    Format detectFileFormat(std::istream &inputStream, bool isRaw = false);

//Format detectFileFormat(const std::uint8_t* data, std::size_t size,
//                        bool isRaw = false);

    std::string format2String(Format format);


}  // namespace odec

#endif  // ODEC_FILE_DETECTOR_H
