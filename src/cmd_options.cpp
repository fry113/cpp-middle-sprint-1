#include "cmd_options.h"
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <iostream>
#include <stdexcept>
#include <string_view>

namespace po = boost::program_options;

namespace CryptoGuard {
ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()                                                                                      //
        ("help,h", "print available options")                                                                //
        ("command,c", po::value<std::string>(), "encrypt/decrypt/checksum")                                  //
        ("input,i", po::value<std::string>(&inputFile_)->default_value("input.txt"), "input file path")      //
        ("output,o", po::value<std::string>(&outputFile_)->default_value("output.txt"), "output file path")  //
        ("password,p", po::value<std::string>(&password_)->default_value("testpwd"), "encryption password");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    // help
    if (vm.contains("help") || vm.empty()) {
        std::cout << desc_ << std::endl;
        return;
    }

    // command
    if (vm.contains("command")) {
        std::string_view cmd(vm["command"].as<std::string>().c_str());
        auto it = commandMapping_.find(cmd);
        if (it != commandMapping_.end()) {
            command_ = commandMapping_.at(cmd);
        } else {
            std::cout << "Unknown command. Please check avaliable commands in help below." << std::endl;
            std::cout << desc_ << std::endl;
            throw std::invalid_argument(vm["command"].as<std::string>());
        }
    }

    // input
    if (vm.contains("input")) {
        inputFile_ = vm["input"].as<std::string>();
    }

    // output
    if (vm.contains("output")) {
        outputFile_ = vm["output"].as<std::string>();
    }

    // password
    if (vm.contains("password")) {
        password_ = vm["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard
