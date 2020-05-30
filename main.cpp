#include <iostream>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "capture.h"

std::mutex m;
std::condition_variable cv;

Capture c;

void capture_thread() {
    c.start(0);

    // Wait until main() sends quit
    std::unique_lock<std::mutex> lk(m);

    {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, []{return !c.isRunning();});
    }

    lk.unlock();
    cv.notify_one();
}

int main() {
    std::thread worker(capture_thread);

    {
        std::lock_guard<std::mutex> lk(m);
    }
    cv.notify_one();


    worker.join();
}
