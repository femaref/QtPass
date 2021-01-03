#include <QUrl>
#include <QUrlQuery>
#include <QString>

#ifdef QT_DEBUG
#include "debughelper.h"
#endif

#include "otp.h"
#include "sha1.h"

#include <stdexcept>

using namespace std;


Bytes::ByteString hmacSha1_64(const Bytes::ByteString & key, const Bytes::ByteString & msg)
{
	return hmacSha1(key, msg, 64);
}

Otp Otp::Create(QString otpurl) {
    otpurl = otpurl.trimmed();
    QUrl url = QUrl(otpurl);
    if (url.scheme() != "otpauth") {
		throw std::invalid_argument("url not of otpauth scheme");
    }

    QUrlQuery query = QUrlQuery(url);

    if (!query.hasQueryItem("secret")) {
		throw std::invalid_argument("no query param secret");
    }

    QString secret = query.queryItemValue("secret");

	std::string normalizedSecret = Otp::normalizedBase32String(secret.toStdString());

	Otp o = Otp(Bytes::fromUnpaddedBase32(normalizedSecret));

	return o;
}

Otp::Otp(const Bytes::ByteString & key) {
	this->secret = key;
}

QString Otp::Generate() {
    uint32_t code = totp(this->secret, time(NULL), 0, 30, 6, hmacSha1_64);

    return QString::number(code).rightJustified(6, '0');
}

std::string Otp::normalizedBase32String(const std::string & unnorm)
{
	std::string ret;

	for (char c : unnorm)
	{
		if (c == ' ' || c == '\n' || c == '-')
		{
			// skip separators
		}
		else if (std::islower(c))
		{
			// make uppercase
			char u = std::toupper(c);
			ret.push_back(u);
		}
		else
		{
			ret.push_back(c);
		}
	}

	return ret;
}

uint32_t Otp::hotp(const Bytes::ByteString & key, uint64_t counter, size_t digitCount, HmacFunc hmacf)
{
	Bytes::ByteString msg = Bytes::u64beToByteString(counter);
	Bytes::ByteStringDestructor dmsg(&msg);

	Bytes::ByteString hmac = hmacf(key, msg);
	Bytes::ByteStringDestructor dhmac(&hmac);

	uint32_t digits10 = 1;
	for (size_t i = 0; i < digitCount; ++i)
	{
		digits10 *= 10;
	}

	// fetch the offset (from the last nibble)
	uint8_t offset = hmac[hmac.size()-1] & 0x0F;

	// fetch the four bytes from the offset
	Bytes::ByteString fourWord = hmac.substr(offset, 4);
	Bytes::ByteStringDestructor dfourWord(&fourWord);

	// turn them into a 32-bit integer
	uint32_t ret =
		(fourWord[0] << 24) |
		(fourWord[1] << 16) |
		(fourWord[2] <<  8) |
		(fourWord[3] <<  0)
	;

	// snip off the MSB (to alleviate signed/unsigned troubles)
	// and calculate modulo digit count
	return (ret & 0x7fffffff) % digits10;
}

uint32_t Otp::totp(const Bytes::ByteString & key, uint64_t timeNow, uint64_t timeStart, uint64_t timeStep, size_t digitCount, HmacFunc hmacf)
{
	uint64_t timeValue = (timeNow - timeStart) / timeStep;
	return hotp(key, timeValue, digitCount, hmacf);
}


