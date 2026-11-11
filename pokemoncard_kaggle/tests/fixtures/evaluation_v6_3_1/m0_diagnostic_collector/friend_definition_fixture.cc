struct FriendHolder {
    int value;
    friend bool operator==(const FriendHolder&, const FriendHolder&) noexcept = default;
};
