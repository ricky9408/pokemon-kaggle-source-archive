constexpr int template_argument_index() {
    return 0;
}

template <int Index>
struct TemplateArgumentTag {};

template <int Index>
constexpr int template_argument_target(TemplateArgumentTag<Index>) {
    return Index + 1;
}

constexpr int explicit_template_argument() {
    return template_argument_target<(template_argument_index())>({});
}

constexpr int template_argument_declaration_target() {
    return 2;
}

template <int (*Function)()>
constexpr int explicit_declaration_template_argument() {
    return Function();
}

static_assert(explicit_template_argument() == 1);
static_assert(
    explicit_declaration_template_argument<&template_argument_declaration_target>() == 2);
