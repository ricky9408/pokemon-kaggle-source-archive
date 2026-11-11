#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <unistd.h>

enum {
    RECEIPT_FD = 3,
    TRACE_FD = 4,
    RECORD_SIZE = 24,
};

static const unsigned char RECORD_MAGIC[8] = {'V', '6', '3', '1', 'W', 'T', '0', '1'};

static void put_be64(unsigned char* output, uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        *output++ = (unsigned char)(value >> shift);
    }
}

static void trace_write(size_t requested, ssize_t result) {
    unsigned char record[RECORD_SIZE];
    for (size_t index = 0; index < sizeof(RECORD_MAGIC); ++index) {
        record[index] = RECORD_MAGIC[index];
    }
    put_be64(record + 8, (uint64_t)requested);
    put_be64(record + 16, result < 0 ? UINT64_MAX : (uint64_t)result);

    size_t offset = 0;
    while (offset < sizeof(record)) {
        const long written = syscall(SYS_write, TRACE_FD, record + offset,
                                     sizeof(record) - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            _exit(125);
        }
        offset += (size_t)written;
    }
}

ssize_t write(int descriptor, const void* buffer, size_t count) {
    const ssize_t result = (ssize_t)syscall(SYS_write, descriptor, buffer, count);
    const int saved_errno = errno;
    if (descriptor == RECEIPT_FD) {
        trace_write(count, result);
    }
    errno = saved_errno;
    return result;
}
