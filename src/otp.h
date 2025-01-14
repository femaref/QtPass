#ifndef OTP_H
#define OTP_H

#include <QString>
#include "bytes.h"
#include "sha1.h"

Bytes::ByteString hmacSha1_64(const Bytes::ByteString & key, const Bytes::ByteString & msg);

class Otp {
    Bytes::ByteString secret;

protected:
    Otp(const Bytes::ByteString & key);
    uint32_t hotp(const Bytes::ByteString & key, uint64_t counter, size_t digitCount, HmacFunc hmacf);
    uint32_t totp(const Bytes::ByteString & key, uint64_t timeNow, uint64_t timeStart, uint64_t timeStep, size_t digitCount, HmacFunc hmacf);

    static std::string normalizedBase32String(const std::string & unnorm);


public:
    static Otp Create(QString);
    virtual ~Otp() {}

    QString Generate();
};

#endif // OTP_H