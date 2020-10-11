//
// Created by dyf on 2020/10/11.
//

#ifndef ODEC_CRC_H
#define ODEC_CRC_H

#include <cstdint>
#include <string>

namespace odec {
namespace utils {

/// compute CRC32 hash, based on Intel's Slicing-by-8 algorithm
/** Usage:
        CRC32 crc32;
        std::string myHash  = crc32("Hello World");     // std::string
        std::string myHash2 = crc32("How are you", 11); // arbitrary data, 11
   bytes

        // or in a streaming fashion:

        CRC32 crc32;
        while (more data available)
          crc32.add(pointer to fresh data, number of new bytes);
        std::string myHash3 = crc32.getHash();

        Note:
        You can find code for the faster Slicing-by-16 algorithm on my website,
   too: http://create.stephan-brumme.com/crc32/ Its unrolled version is about
   twice as fast but its look-up table doubled in size as well.
*/
//: public Hash
class CRC32 {
public:
    /// hash is 4 bytes long
    enum { HashBytes = 4 };

    /// same as reset()
    CRC32();

    /// compute CRC32 of a memory block
    std::string operator()(const void* data, size_t numBytes);
    /// compute CRC32 of a string, excluding final zero
    std::string operator()(const std::string& text);

    /// add arbitrary number of bytes
    void add(const void* data, size_t numBytes);

    /// return latest hash as 8 hex characters
    std::string getHash() const;
    /// return latest hash as bytes
    void getHash(unsigned char buffer[CRC32::HashBytes]) const;

    /// restart
    void reset();

private:
    /// hash
    uint32_t m_hash{};
};

}  // namespace utils
}  // namespace odec
#endif  // ODEC_CRC_H
