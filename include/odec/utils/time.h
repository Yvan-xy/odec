//
// Created by dyf on 2020/10/3.
//

#ifndef ODEC_TIME_H
#define ODEC_TIME_H

#include <ctime>
#include <string>

namespace odec {
    namespace utils {

        std::tm *getCurrentTimestamp();

        std::string getCurrentDate();

        std::string getCurrentTime();

        std::string getCurrentYear();

        std::string timestampToDate(std::tm *tm);

        std::string timestampToDate(std::time_t timestamp);

        double getElapsedTime();

    } // namespace utils
} // namespace odec

#endif //ODEC_TIME_H
