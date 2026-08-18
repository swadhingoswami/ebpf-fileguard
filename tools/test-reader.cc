// test-reader — an *unauthorized* process in the demo. Identical behaviour to
// backup-agent but a different executable image, hence a different FileGuard
// identity. Demonstrates that policy is keyed on the executable, not the
// behaviour or argv[0].
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: test-reader <file>\n";
        return 2;
    }
    const std::string path = argv[1];
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "test-reader: " << path << ": Permission denied.\n";
        return 1;
    }
    std::string contents((std::istreambuf_iterator<char>(in)),
                         std::istreambuf_iterator<char>());
    std::cout << "Access allowed.\n";
    std::cout << contents;
    if (!contents.empty() && contents.back() != '\n') std::cout << '\n';
    return 0;
}
