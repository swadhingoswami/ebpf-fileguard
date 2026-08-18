#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <utility>
#include <vector>

namespace fileguard {

// Bounded single-producer / single-consumer queue.
//
// This is the ONLY cross-thread event queue in the system. The eBPF ring
// buffer is polled by a single thread (the producer) and the event logger runs
// on a single thread (the consumer). Because there is exactly one producer and
// one consumer, the data path itself is lock-free (atomic head/tail on a
// preallocated ring). A mutex + two condition variables are used only to block
// the producer when the ring is full and the consumer when it is empty — i.e.
// for backpressure, not for the data transfer itself.
//
// Why not a fully lock-free design with a wait-free consumer? A blocking
// consumer gives the logger bounded memory even under a denial-of-service
// flood of events: if the ring fills, the poller stalls instead of growing
// memory or dropping events. See docs/11-concurrency.md.
template <typename T>
class SpscQueue {
public:
    explicit SpscQueue(size_t capacity) : slots_(capacity) {
        if (capacity < 2) throw std::invalid_argument("SpscQueue capacity must be >= 2");
    }

    SpscQueue(const SpscQueue&) = delete;
    SpscQueue& operator=(const SpscQueue&) = delete;

    // Blocks while the ring is full. Safe to call from the producer thread.
    void push(T item) {
        {
            std::unique_lock<std::mutex> lock(mtx_);
            cv_producer_.wait(lock, [&] { return stop_ || !full(); });
            if (stop_) return;
            slots_[head_.load(std::memory_order_relaxed)] = std::move(item);
            head_.store(next(head_.load(std::memory_order_relaxed)),
                        std::memory_order_release);
        }
        cv_consumer_.notify_one();
    }

    // Non-blocking push; returns false if the ring is full.
    bool try_push(T item) {
        const size_t h = head_.load(std::memory_order_relaxed);
        const size_t t = tail_.load(std::memory_order_acquire);
        if (next(h) == t) return false;  // full
        slots_[h] = std::move(item);
        head_.store(next(h), std::memory_order_release);
        cv_consumer_.notify_one();
        return true;
    }

    // Blocks while the ring is empty; returns false after stop() once drained.
    bool pop(T& out) {
        std::unique_lock<std::mutex> lock(mtx_);
        cv_consumer_.wait(lock, [&] { return stop_ || !empty(); });
        if (empty()) return false;  // stopped and drained
        out = std::move(slots_[tail_.load(std::memory_order_relaxed)]);
        tail_.store(next(tail_.load(std::memory_order_relaxed)),
                    std::memory_order_release);
        lock.unlock();
        cv_producer_.notify_one();
        return true;
    }

    bool try_pop(T& out) {
        const size_t h = head_.load(std::memory_order_acquire);
        const size_t t = tail_.load(std::memory_order_relaxed);
        if (h == t) return false;  // empty
        out = std::move(slots_[t]);
        tail_.store(next(t), std::memory_order_release);
        cv_producer_.notify_one();
        return true;
    }

    // Unblocks any blocked producer/consumer; after stop, pop() returns false
    // once the ring drains. Call exactly once, from the controller.
    void request_stop() {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            stop_ = true;
        }
        cv_producer_.notify_all();
        cv_consumer_.notify_all();
    }

    [[nodiscard]] size_t capacity() const { return slots_.size(); }
    [[nodiscard]] bool empty() const {
        return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
    }
    [[nodiscard]] bool full() const {
        return next(head_.load(std::memory_order_relaxed)) == tail_.load(std::memory_order_acquire);
    }

private:
    size_t next(size_t i) const noexcept { return (i + 1) % slots_.size(); }

    std::vector<T> slots_;
    std::atomic<size_t> head_{0};  // producer index
    std::atomic<size_t> tail_{0};  // consumer index
    std::mutex mtx_;
    std::condition_variable cv_producer_;
    std::condition_variable cv_consumer_;
    bool stop_ = false;
};

}  // namespace fileguard
