//
// Created by dyf on 2020/10/10.
//
#include <iostream>

#include "odec/fileinfo/util/format_detector.h"

using namespace odec::fileinfo;

int main() {
    std::string filePath = "a.elf";
    auto fileFormat = detectFileFormat(filePath);
    std::string formatString = format2String(fileFormat);
    std::cout << "File " << filePath << " is " << formatString << std::endl;
    return 0;
}