#ifndef EVALUATION_V6_3_1_CAPTURE_V2_OWNED_FD_H
#define EVALUATION_V6_3_1_CAPTURE_V2_OWNED_FD_H

#include <unistd.h>

namespace evaluation_v6_3_1::capture_v2 {

class OwnedFd final {
public:
    OwnedFd() noexcept = default;
    explicit OwnedFd(int descriptor) noexcept : descriptor_(descriptor) {}
    ~OwnedFd() noexcept { reset(); }

    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;

    OwnedFd(OwnedFd&& other) noexcept : descriptor_(other.release()) {}

    OwnedFd& operator=(OwnedFd&& other) noexcept {
        if (this != &other) {
            reset(other.release());
        }
        return *this;
    }

    [[nodiscard]] int get() const noexcept { return descriptor_; }
    [[nodiscard]] explicit operator bool() const noexcept { return descriptor_ >= 0; }

    [[nodiscard]] int release() noexcept {
        const int descriptor = descriptor_;
        descriptor_ = -1;
        return descriptor;
    }

    void reset(int descriptor = -1) noexcept {
        if (descriptor_ >= 0) {
            static_cast<void>(::close(descriptor_));
        }
        descriptor_ = descriptor;
    }

private:
    int descriptor_ = -1;
};

}  // namespace evaluation_v6_3_1::capture_v2

#endif  // EVALUATION_V6_3_1_CAPTURE_V2_OWNED_FD_H
