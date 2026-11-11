#include <functional>

struct FirstCallable {
    void operator()() const noexcept {}
};

struct SecondCallable {
    void operator()() const noexcept {}
};

static_assert(noexcept(std::invoke(FirstCallable{})));
static_assert(noexcept(std::invoke(SecondCallable{})));

int definition_instance_collision_fixture() {
    std::invoke(FirstCallable{});
    std::invoke(SecondCallable{});
    return 0;
}
