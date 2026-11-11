constexpr int declarator_type_probe() {
    return 1;
}

template <typename Value>
int declarator_type_expression(Value value) {
    struct Local {
        decltype(declarator_type_probe()) field;
    };
    Local local{value};
    return local.field;
}

int instantiate_declarator_type_expression() {
    return declarator_type_expression(7);
}
