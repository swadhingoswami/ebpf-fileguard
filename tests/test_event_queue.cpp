#include <catch2/catch_test_macros.hpp>

#include "fileguard/event_queue.hpp"

using namespace fileguard;

TEST_CASE("SpscQueue preserves FIFO order", "[queue]") {
    SpscQueue<int> q(8);
    for (int i = 0; i < 5; ++i) q.push(i);
    for (int i = 0; i < 5; ++i) {
        int v = -1;
        REQUIRE(q.try_pop(v));
        CHECK(v == i);
    }
    int v = -1;
    CHECK_FALSE(q.try_pop(v));
}

TEST_CASE("SpscQueue refuses pushes when full", "[queue]") {
    SpscQueue<int> q(4);  // capacity 4 -> 3 usable slots
    CHECK(q.try_push(1));
    CHECK(q.try_push(2));
    CHECK(q.try_push(3));
    CHECK_FALSE(q.try_push(4));
    int v = -1;
    REQUIRE(q.try_pop(v));
    CHECK(v == 1);
    CHECK(q.try_push(4));
}

TEST_CASE("SpscQueue drains remaining items after stop", "[queue]") {
    SpscQueue<int> q(8);
    q.push(1);
    q.push(2);
    q.push(3);
    q.request_stop();
    int v = -1;
    REQUIRE(q.pop(v));
    CHECK(v == 1);
    REQUIRE(q.pop(v));
    CHECK(v == 2);
    REQUIRE(q.pop(v));
    CHECK(v == 3);
    // Now empty and stopped.
    CHECK_FALSE(q.pop(v));
}
