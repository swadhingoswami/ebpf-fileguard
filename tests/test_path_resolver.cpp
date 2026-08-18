#include <catch2/catch_test_macros.hpp>

#include "fileguard/path_resolver.hpp"

using namespace fileguard;

TEST_CASE("PathResolver resolves known ids and formats unknown ones", "[resolver]") {
    PathResolver r;
    FileId known;
    known.dev_major = 1;
    known.dev_minor = 2;
    known.ino = 99;
    r.add(known, "/protected/secret.txt");
    CHECK(r.resolve(known) == "/protected/secret.txt");

    FileId unknown;
    unknown.dev_major = 3;
    unknown.dev_minor = 4;
    unknown.ino = 55;
    CHECK(r.resolve(unknown) == "3:4:55");
}
