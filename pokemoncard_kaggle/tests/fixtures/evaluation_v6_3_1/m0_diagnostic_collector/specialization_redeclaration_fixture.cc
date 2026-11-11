template <typename Value>
int specialization_probe(Value value) {
    return static_cast<int>(value) + 1;
}

template <>
int specialization_probe<int>(int value) {
    return value + 2;
}

int declaration_only(int value);

int redeclared_definition(int value);

int redeclared_definition(int value) {
    return value + 3;
}

int redeclared_definition(int value);

int instantiate_specializations() {
    return specialization_probe(1) + specialization_probe(2.0) +
           redeclared_definition(3);
}
