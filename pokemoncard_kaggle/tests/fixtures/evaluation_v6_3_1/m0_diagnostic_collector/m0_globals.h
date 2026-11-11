struct HeaderDestructed {
    constexpr HeaderDestructed() = default;
    ~HeaderDestructed() {}
};

inline int header_constant = 9;
inline HeaderDestructed header_destructed{};
inline int header_empty;
