#include "../include/cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);

        CryptoGuard::CryptoGuardCtx cryptoCtx;
        std::fstream inputFile, outputFile;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            inputFile.open(options.GetInputFile(), std::ios_base::in);
            if (!inputFile.is_open()) {
                throw std::runtime_error{"Cannot open inputFile"};
            }
            outputFile.open(options.GetOutputFile(), std::ios_base::out);
            if (!outputFile.is_open()) {
                throw std::runtime_error{"Cannot open outputFile"};
            }
            cryptoCtx.EncryptFile(inputFile, outputFile, options.GetPassword());
            std::print("File encoded successfully\n");
            inputFile.close();
            outputFile.close();
            break;

        case COMMAND_TYPE::DECRYPT:
            inputFile.open(options.GetInputFile(), std::ios_base::in);
            if (!inputFile.is_open()) {
                throw std::runtime_error{"Cannot open inputFile"};
            }
            outputFile.open(options.GetOutputFile(), std::ios_base::out);
            if (!outputFile.is_open()) {
                throw std::runtime_error{"Cannot open outputFile"};
            }
            cryptoCtx.DecryptFile(inputFile, outputFile, options.GetPassword());
            std::print("File decoded successfully\n");
            inputFile.close();
            outputFile.close();
            break;

        case COMMAND_TYPE::CHECKSUM:
            inputFile.open(options.GetInputFile(), std::ios_base::in);
            if (!inputFile.is_open()) {
                throw std::runtime_error{"Cannot open inputFile"};
            }
            std::print("Checksum: {}\n", cryptoCtx.CalculateChecksum(inputFile));
            inputFile.close();
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}