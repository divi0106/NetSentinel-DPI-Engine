#pragma once
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

template<typename T>
class TSQueue {
public:
    explicit TSQueue(size_t max_size = 4096)
        : max_size_(max_size) {}

    void push(T item) {
        std::unique_lock<std::mutex> lk(mtx_);
        not_full_.wait(lk, [&]{
            return q_.size() < max_size_ || done_;
        });
        if (done_) return;
        q_.push(std::move(item));
        not_empty_.notify_one();
    }

    std::optional<T> pop() {
        std::unique_lock<std::mutex> lk(mtx_);
        not_empty_.wait(lk, [&]{
            return !q_.empty() || done_;
        });
        if (q_.empty()) return std::nullopt;
        T item = std::move(q_.front());
        q_.pop();
        not_full_.notify_one();
        return item;
    }

    void setDone() {
        std::lock_guard<std::mutex> lk(mtx_);
        done_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }

    size_t size() {
        std::lock_guard<std::mutex> lk(mtx_);
        return q_.size();
    }

    bool empty() {
        std::lock_guard<std::mutex> lk(mtx_);
        return q_.empty();
    }

private:
    std::queue<T>           q_;
    std::mutex              mtx_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t                  max_size_;
    bool                    done_ = false;
};