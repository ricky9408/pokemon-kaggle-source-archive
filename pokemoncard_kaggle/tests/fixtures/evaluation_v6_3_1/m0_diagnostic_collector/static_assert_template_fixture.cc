#include <type_traits>

template <typename Value>
int static_assert_template(Value value) {
    static_assert(std::is_integral<Value>{}, "Value must be integral");
    return value <= 0 ? 0 : 1;
}

int instantiate_static_assert_template() {
    return static_assert_template(1);
}
