//
// Created by dyf on 2020/10/11.
//

#include "odec/fileinfo/util/crypto.h"

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <vector>

#include "odec/utils/conversion.h"
#include "odec/utils/crc32.h"

namespace odec::fileinfo {

    /**
     * @brief Count CRC32 of @a data.
     * @param[in] data Input data.
     * @param[in] length Length of input data.
     * @return CRC32 of input data.
     */
    std::string getCrc32(const unsigned char *data, std::uint64_t length) {
        odec::utils::CRC32 crc;
        return crc(data, length);
    }

    /**
     * @brief Count MD5 of @a data.
     * @param[in] data Input data.
     * @param[in] length Length of input data.
     * @return MD5 of input data.
     */
    std::string getMd5(const unsigned char *data, std::uint64_t length) {
        std::vector<unsigned char> digest(MD5_DIGEST_LENGTH);
        MD5(data, length, digest.data());

        std::string md5;
        odec::utils::bytesToHexString(digest, md5, 0, 0, false);
        return md5;
    }

    std::string getSha1(const unsigned char *data, std::uint64_t length) {
        std::vector<unsigned char> digest(SHA_DIGEST_LENGTH);
        SHA1(data, length, digest.data());

        std::string sha1;
        odec::utils::bytesToHexString(digest, sha1, 0, 0, false);
        return sha1;
    }

    std::string getSha256(const unsigned char *data, std::uint64_t length) {
        std::vector<unsigned char> digest(SHA256_DIGEST_LENGTH);
        SHA256(data, length, digest.data());

        std::string sha256;
        odec::utils::bytesToHexString(digest, sha256, 0, 0, false);
        return sha256;
    }

}  // namespace odec::fileinfo
