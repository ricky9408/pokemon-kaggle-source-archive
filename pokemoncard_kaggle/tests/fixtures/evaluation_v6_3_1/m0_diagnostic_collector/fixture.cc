#include "m0_globals.h"

int runtime_seed() {
    return 7;
}

int zero_global;
const int constant_global = 11;
constinit int constinit_global = 12;
int dynamic_global = runtime_seed();
thread_local int thread_global = runtime_seed();
extern int extern_declaration_only;

struct Destructed {
    constexpr explicit Destructed(int value = 0) : value(value) {}
    ~Destructed() {}
    int value;
};

Destructed destructed_global{};
Destructed dynamic_destructed_global{runtime_seed()};

struct StaticMemberHolder {
    static int static_member;
};

int StaticMemberHolder::static_member = 13;

template <typename T>
inline int variable_template_value = 0;

template <>
int variable_template_value<int> = 14;

template <typename T>
T template_primary(T value) {
    return value;
}

template <>
int template_primary<int>(int value) {
    return value + 1;
}

template long template_primary<long>(long);

int template_calls() {
    static int local_static = runtime_seed();
    const int explicit_specialization = template_primary(3);
    const long explicit_instantiation = template_primary(4L);
    return local_static + explicit_specialization + static_cast<int>(explicit_instantiation) +
           static_cast<int>(template_primary(5.0));
}

int probe() {
    return 1;
}

static int internal_linkage_probe() {
    return 2;
}

template <typename T>
concept CanProbe = requires { probe(); };

int requires_and_runtime() {
    static_assert(CanProbe<int>);
    return probe() + internal_linkage_probe();
}

int va_arg_wrapper(__builtin_va_list values) {
    return __builtin_va_arg(values, int);
}
