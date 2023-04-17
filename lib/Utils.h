#ifndef _MONGOOSE_UTILS_H
#define _MONGOOSE_UTILS_H

#include <iostream>
#include <openssl/sha.h>

namespace Mongoose
{
    class Utils
    {
        public:
            static std::string htmlEntities(const std::string& data);
            static void sleep(int ms);
            static int getTime();
            static void randomAlphanumericString(char *, int length = 30);
            static std::string sanitizeFilename(const std::string& filename);
            static void sha256(const char *string, char outputBuffer[65]);
    };
}

#endif

