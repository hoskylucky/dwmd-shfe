#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <lcxx/identifiers/hardware.hpp>
#include <lcxx/identifiers/os.hpp>
#include <lcxx/lcxx.hpp>

// Can also be loaded from file
constexpr auto private_key = R"(
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQCnR/pV5N+Nv9WcYIlwJTN3Lp2w4LHo9GCQJKnmBP8Ch7ouqKCJ
+LmRlU0VoCLlN76JXxjAtpcOLbrZrNZQR5OlcgC9pONBNimQkQgGQWzqN9EA3GhH
cMrkUg+ddRO0lBE9eJ0IomBKfwIFOvrbaMwVYX6yAnNbulUgSaBk16G41QIDAQAB
AoGAC6bq3BLOM5x6L6NVz3b358RafZiZK+Xh2AiFwRz1+mIj6N4cGKA3pNlmfiwi
Yh8I6Z6zJbFSQk2TJ1hvsTXbJd0+2rWs+QRJWEHB+O5X/IGW7YqmhmyLO9r9Yu0H
+RhEdCdfiVPNPuBLGuWNy73jvqA/IcxZj+PVhfqrAo/gqgECQQDSKLkDAQCwyIi6
ODlwv7NVo+pvrIFD3XvSxCUhoI/dKC/CfxjgzN3KuHAU9k+Bn0wQ7HNfOzao7LRQ
X0nMc5hVAkEAy8T0K+lkLDGAWMonTwbklWE7zAH7DdKi3OB57cjTKY+Vi0pBca/8
oOKcdTfl7V9XMdqHHtpeE/bfX4ry12gegQJBAKh8B192JVSVYLBStRJETgUBpcij
9voujb+6ir472DqIpkl61bob5FBKr2jO04zq5fPHbPNTKI4jPqgUzLiBkAUCQCnx
hpkrV3VJUzPzmJfJwW+GLjrWBYlY3DE++5oYhm69oXikdkgig4vSWYY/VVLBFz+p
zbpqFIdjf6M5BLeWNQECQQChEMMmbZHZRXueSBKan1ET27wjIG8nX91SDCBrD7NY
2oMVbCDRTKd0mgpbtr3Cx8KpN0KpyvuSd6E+TXbq9ris
-----END RSA PRIVATE KEY-----
)";

#include <cxxopts.hpp>

auto main(int argc, char *argv[]) -> int
{
    cxxopts::Options options("key_gen", "A program to generate a license key");

    options.add_options()("o,output", "output file", cxxopts::value<std::string>())(
        "os",
        "os hash",
        cxxopts::value<std::string>())("hw", "hardware hash", cxxopts::value<std::string>())(
        "date",
        "yyyymmdd",
        cxxopts::value<std::string>())("h,help", "Print usage");

    auto result = options.parse(argc, argv);

    if (result.count("help"))
    {
        std::cout << options.help() << std::endl;
        return 0;
    }

    if (!result.count("os"))
    {
        std::cerr << "os hash is required" << std::endl;
        return 1;
    }

    if (!result.count("hw"))
    {
        std::cerr << "hardware hash is required" << std::endl;
        return 1;
    }

    if (!result.count("date"))
    {
        std::cerr << "date is required" << std::endl;
        return 1;
    }

    lcxx::license license;

    // Push optional data into the license file
    license.push_content("hardware", result["hw"].as<std::string>());
    license.push_content("os", result["os"].as<std::string>());
    license.push_content("date", result["date"].as<std::string>());

    auto key =
        lcxx::crypto::load_key(std::string{private_key}, lcxx::crypto::key_type::private_key);
    std::string json_output = lcxx::to_json(license, key).dump(4);

    std::string output_file = "license.json";
    if (result.count("output"))
        output_file = result["output"].as<std::string>();
    std::ofstream ofs(output_file);
    if (!ofs)
    {
        std::cerr << "Failed to open output file: " << output_file << std::endl;
        return 1;
    }
    ofs << json_output;
    ofs.close();

    return 0;
}
