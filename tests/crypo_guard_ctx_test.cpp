#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <ios>
#include <sstream>

TEST(CryptoGuardCtx, EncryptCheck1) {
    std::vector<unsigned char> cntrlVal{216, 134, 127, 87, 197, 73, 54,  47,  77,  171, 242, 234, 225, 170, 136, 14,
                                        205, 80,  77,  39, 116, 86, 204, 189, 148, 168, 167, 63,  126, 183, 27,  48};
    std::vector<unsigned char> checkVal(32);
    std::string input = "01234567890123456789";
    std::string password = "12341234";
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream, outStream;
    inStream.write(reinterpret_cast<const char *>(input.data()), input.size());

    cryptoCtx.EncryptFile(inStream, outStream, password);

    outStream.read(reinterpret_cast<char *>(checkVal.data()), checkVal.size());
    EXPECT_EQ(checkVal, cntrlVal);
}

TEST(CryptoGuardCtx, EncryptCheck2) {
    std::vector<unsigned char> cntrlVal{32,  228, 223, 69,  126, 196, 179, 195, 105, 88,  86,  121, 175, 204, 136, 229,
                                        87,  48,  121, 246, 81,  164, 15,  7,   149, 181, 88,  39,  21,  242, 68,  38,
                                        73,  82,  104, 235, 182, 227, 66,  163, 12,  147, 29,  120, 54,  20,  95,  34,
                                        178, 140, 125, 146, 195, 172, 39,  135, 238, 134, 188, 81,  224, 112, 47,  224,
                                        164, 98,  14,  6,   204, 52,  71,  53,  74,  210, 63,  71,  158, 235, 198, 58,
                                        155, 19,  219, 42,  164, 167, 24,  63,  99,  107, 34,  34,  85,  18,  129, 184};
    std::vector<unsigned char> checkVal(96, 0);
    std::string input = "veryVeryLongString withSpaceBars 1234567890 1234567890 1234567890 1234567890 1234567890";
    std::string password = "longPasswordToo_1234567890";
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream, outStream;
    inStream.write(reinterpret_cast<const char *>(input.data()), input.size());

    cryptoCtx.EncryptFile(inStream, outStream, password);

    outStream.read(reinterpret_cast<char *>(checkVal.data()), checkVal.size());
    EXPECT_EQ(checkVal, cntrlVal);
}

TEST(CryptoGuardCtx, EncryptThrowCheck) {
    std::string input = "01234567890123456789";
    std::string password = "12341234";
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream;
    inStream.write(reinterpret_cast<const char *>(input.data()), input.size());

    ASSERT_THROW(cryptoCtx.EncryptFile(inStream, inStream, password), std::runtime_error);
}

TEST(CryptoGuardCtx, DecryptCheck1) {
    std::vector<unsigned char> input{216, 134, 127, 87, 197, 73, 54,  47,  77,  171, 242, 234, 225, 170, 136, 14,
                                     205, 80,  77,  39, 116, 86, 204, 189, 148, 168, 167, 63,  126, 183, 27,  48};
    std::string checkVal;
    std::string cntrlVal = "01234567890123456789";
    std::string password = "12341234";
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream, outStream;
    inStream.write(reinterpret_cast<const char *>(input.data()), input.size());

    cryptoCtx.DecryptFile(inStream, outStream, password);

    checkVal = outStream.str();
    EXPECT_EQ(checkVal, cntrlVal);
}

TEST(CryptoGuardCtx, DecryptCheck2) {
    std::vector<unsigned char> input{32,  228, 223, 69,  126, 196, 179, 195, 105, 88,  86,  121, 175, 204, 136, 229,
                                     87,  48,  121, 246, 81,  164, 15,  7,   149, 181, 88,  39,  21,  242, 68,  38,
                                     73,  82,  104, 235, 182, 227, 66,  163, 12,  147, 29,  120, 54,  20,  95,  34,
                                     178, 140, 125, 146, 195, 172, 39,  135, 238, 134, 188, 81,  224, 112, 47,  224,
                                     164, 98,  14,  6,   204, 52,  71,  53,  74,  210, 63,  71,  158, 235, 198, 58,
                                     155, 19,  219, 42,  164, 167, 24,  63,  99,  107, 34,  34,  85,  18,  129, 184};
    std::string checkVal;
    std::string cntrlVal = "veryVeryLongString withSpaceBars 1234567890 1234567890 1234567890 1234567890 1234567890";
    std::string password = "longPasswordToo_1234567890";
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream, outStream;
    inStream.write(reinterpret_cast<const char *>(input.data()), input.size());

    cryptoCtx.DecryptFile(inStream, outStream, password);

    checkVal = outStream.str();
    EXPECT_EQ(checkVal, cntrlVal);
}

TEST(CryptoGuardCtx, DecryptThrowCheck) {
    std::vector<unsigned char> input{216, 134, 127, 87, 197, 73, 54,  47,  77,  171, 242, 234, 225, 170, 136, 14,
                                     205, 80,  77,  39, 116, 86, 204, 189, 148, 168, 167, 63,  126, 183, 27,  48};
    std::string checkVal;
    const std::string cntrlVal = "01234567890123456789";
    std::string password = "12341234";
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream, outStream;
    inStream.write(reinterpret_cast<const char *>(input.data()), input.size());

    outStream.setstate(std::ios_base::badbit);
    ASSERT_THROW(cryptoCtx.DecryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuardCtx, ChecksumCheck1) {
    std::string input = "01234567890123456789";
    std::string cntrlVal = "4e76ad8354461437c04ef9b9b242540b6406d782ff2c3fb28afdab5b423f88fe";

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream;
    inStream.write(reinterpret_cast<const char *>(input.data()), input.size());

    std::string checkVal = cryptoCtx.CalculateChecksum(inStream);

    EXPECT_EQ(checkVal, cntrlVal);
}

TEST(CryptoGuardCtx, ChecksumCheck2) {
    std::string input = "veryVeryLongString_blablablaBLA! with spacebars! 1234567890 1234567890 1234567890 1234567890";
    std::string cntrlVal = "92e2a2aedfe75206f1281771823f61605367a7eeb7533a310994ea7d49705870";

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream;
    inStream.write(reinterpret_cast<const char *>(input.data()), input.size());

    std::string checkVal = cryptoCtx.CalculateChecksum(inStream);

    EXPECT_EQ(checkVal, cntrlVal);
}

TEST(CryptoGuardCtx, EmptyPassCheck) {
    std::vector<unsigned char> cntrlVal{32,  228, 223, 69,  126, 196, 179, 195, 105, 88,  86,  121, 175, 204, 136, 229,
                                        87,  48,  121, 246, 81,  164, 15,  7,   149, 181, 88,  39,  21,  242, 68,  38,
                                        73,  82,  104, 235, 182, 227, 66,  163, 12,  147, 29,  120, 54,  20,  95,  34,
                                        178, 140, 125, 146, 195, 172, 39,  135, 238, 134, 188, 81,  224, 112, 47,  224,
                                        164, 98,  14,  6,   204, 52,  71,  53,  74,  210, 63,  71,  158, 235, 198, 58,
                                        155, 19,  219, 42,  164, 167, 24,  63,  99,  107, 34,  34,  85,  18,  129, 184};
    std::vector<unsigned char> checkVal(96, 0);
    std::string input = "veryVeryLongString withSpaceBars 1234567890 1234567890 1234567890 1234567890 1234567890";
    std::string password = "";
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream, outStream;
    inStream.write(reinterpret_cast<const char *>(input.data()), input.size());

    ASSERT_THROW(cryptoCtx.EncryptFile(inStream, outStream, password), std::runtime_error);
}

TEST(CryptoGuardCtx, EncryptDecryptChecksumCheck) {
    std::string input = "veryVeryLongString_blablablaBLA! with spacebars! 1234567890 1234567890 1234567890 1234567890";
    std::string password = "casual_pwd";
    CryptoGuard::CryptoGuardCtx cryptoCtx;
    std::stringstream inStream, out1Stream, out2Stream;
    inStream.write(reinterpret_cast<const char *>(input.data()), input.size());

    cryptoCtx.EncryptFile(inStream, out1Stream, password);
    cryptoCtx.DecryptFile(out1Stream, out2Stream, password);

    EXPECT_EQ(cryptoCtx.CalculateChecksum(inStream), cryptoCtx.CalculateChecksum(out2Stream));
}