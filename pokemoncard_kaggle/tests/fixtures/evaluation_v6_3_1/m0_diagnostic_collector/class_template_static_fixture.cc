template <typename Value>
struct ClassTemplateStaticHolder {
    static int value;
};

template <typename Value>
int ClassTemplateStaticHolder<Value>::value = 17;

template struct ClassTemplateStaticHolder<int>;

int read_class_template_static() {
    return ClassTemplateStaticHolder<int>::value;
}
