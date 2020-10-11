//
// Created by dyf on 2020/10/11.
//

#ifndef ODEC_CRYPTO_H
#define ODEC_CRYPTO_H

#include <cstdint>
#include <string>

namespace odec::fileinfo {

    std::string getCrc32(const unsigned char *data, std::uint64_t length);

    std::string getMd5(const unsigned char *data, std::uint64_t length);

    std::string getSha1(const unsigned char *data, std::uint64_t length);

    std::string getSha256(const unsigned char *data, std::uint64_t length);

}  // namespace odec::fileinfo
#endif  // ODEC_CRYPTO_H
