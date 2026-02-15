#include "cmd_options.h"
#include <gtest/gtest.h>

using ct = CryptoGuard::ProgramOptions::COMMAND_TYPE;

TEST(ProgramOptions, ChecksumTest) {
    int argCount = 3;
    char *testCmdLine[] = {"", "--command", "checksum"};

    CryptoGuard::ProgramOptions options;
    options.Parse(argCount, testCmdLine);

    EXPECT_EQ(options.GetCommand(), ct::CHECKSUM);
}

TEST(ProgramOptions, EncryptTest) {
    int argCount = 7;
    char *testCmdLine[] = {"", "-c", "encrypt", "-i", "input.txt", "--output", "output.txt"};

    CryptoGuard::ProgramOptions options;
    options.Parse(argCount, testCmdLine);

    EXPECT_EQ(options.GetCommand(), ct::ENCRYPT);
}

TEST(ProgramOptions, DecryptTest) {
    int argCount = 3;
    char *testCmdLine[] = {"", "-c", "decrypt"};

    CryptoGuard::ProgramOptions options;
    options.Parse(argCount, testCmdLine);

    EXPECT_EQ(options.GetCommand(), ct::DECRYPT);
}

TEST(ProgramOptions, InputFileTest) {
    int argCount = 7;
    char *testCmdLine[] = {"", "-c", "encrypt", "-i", "input.txt", "--output", "output.txt"};

    CryptoGuard::ProgramOptions options;
    options.Parse(argCount, testCmdLine);

    EXPECT_EQ(options.GetInputFile(), "input.txt");
}

TEST(ProgramOptions, OutputFileTest) {
    int argCount = 3;
    char *testCmdLine[] = {"", "-c", "encrypt"};

    CryptoGuard::ProgramOptions options;
    options.Parse(argCount, testCmdLine);

    EXPECT_EQ(options.GetOutputFile(), "output.txt");
}

TEST(ProgramOptions, ShortParamsCheck) {
    int argCount = 5;
    char *testCmdLine[] = {"", "-c", "checksum", "-i", "input.txt"};

    CryptoGuard::ProgramOptions options;
    options.Parse(argCount, testCmdLine);

    EXPECT_EQ(options.GetCommand(), ct::CHECKSUM);
}

TEST(ProgramOptions, ExceptionTest) {
    int argCount = 7;
    char *testCmdLine[] = {"", "-c", "encode", "-i", "input.txt", "--output", "output.txt"};

    CryptoGuard::ProgramOptions options;

    EXPECT_THROW(options.Parse(argCount, testCmdLine), std::invalid_argument);
}