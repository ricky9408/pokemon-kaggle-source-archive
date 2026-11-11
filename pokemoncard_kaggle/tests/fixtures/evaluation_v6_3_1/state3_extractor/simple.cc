#include "include_once.h"
#include "include_once.h"

struct FixtureBox {
    explicit FixtureBox(int input) : value(input) {}

    int read() const {
        return value;
    }

    int value;
};

int fixture_caller() {
    FixtureBox box(fixture_increment(7));
    return box.read();
}
