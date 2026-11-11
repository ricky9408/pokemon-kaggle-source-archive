#include <type_traits>

int read_integral_constant() {
    return std::integral_constant<bool, true>::value ? 1 : 0;
}
