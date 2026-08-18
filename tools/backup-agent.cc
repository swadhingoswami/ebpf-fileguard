// backup-agent — the *authorized* process in the demo. It is a real, compiled
// executable; its identity in FileGuard is the path to this executable image.
//
// Usage: backup-agent /path/to/file
// On success it prints the file contents; on failure it prints the error.
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: backup-agent <file>\n";
        return 2;
    }
    const std::string path = argv[1];
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "backup-agent: " << path << ": Permission denied.\n";
        return 1;
    }
    std::string contents((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
    std::cout << "Access allowed.\n";
    std::cout << contents;
    if (!contents.empty() && contents.back() != '\n') std::cout << '\n';
    return 0;
}
