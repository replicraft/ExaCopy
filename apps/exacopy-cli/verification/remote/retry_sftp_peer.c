/* Bounded read-only SFTP v3 fixture for a dedicated OpenSSH chroot. */
#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef EXACOPY_FIXTURE_ROOT
#define EXACOPY_FIXTURE_ROOT ""
#endif

#define INPUT EXACOPY_FIXTURE_ROOT "/retry-input/"
#define STATE EXACOPY_FIXTURE_ROOT "/retry-state/"
#define CONTROL EXACOPY_FIXTURE_ROOT "/retry-control/"
#define MAX_REQUEST 4096
#define MAX_READ 32768
#define SOURCE_BYTES (3 * 65536)
#define FAULT_OFFSET 65536
#define MAX_REQUESTS 120
#define WAIT_MS 28000
#define COMMAND "exacopy-fixture-sftp-v1"

enum { INIT = 1, VERSION = 2, OPEN = 3, CLOSE = 4, READ = 5, LSTAT = 7,
       FSTAT = 8, STAT = 17, STATUS = 101, HANDLE = 102, DATA = 103, ATTRS = 105 };

struct input { const unsigned char *bytes; size_t left; };
struct packet { unsigned char bytes[MAX_READ + 16]; size_t end; };
struct session {
    const char *name;
    int trace;
    int file;
    unsigned attempt;
};

static const char *const cases[] = {"redial", "expired", "revoked", "budget", "host-refused"};

static bool exact_io(int fd, void *buffer, size_t length, bool output) {
    unsigned char *bytes = buffer;
    for (unsigned interrupted = 0; length; ) {
        ssize_t count = output ? write(fd, bytes, length) : read(fd, bytes, length);
        if (count < 0 && errno == EINTR && interrupted < 16) {
            interrupted++;
            continue;
        }
        if (count <= 0) return false;
        bytes += (size_t)count;
        length -= (size_t)count;
        interrupted = 0;
    }
    return true;
}

static bool take32(struct input *input, uint32_t *number) {
    if (input->left < 4) return false;
    const unsigned char *p = input->bytes;
    *number = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    input->bytes += 4;
    input->left -= 4;
    return true;
}

static bool take64(struct input *input, uint64_t *number) {
    uint32_t first, second;
    if (!take32(input, &first) || !take32(input, &second)) return false;
    *number = (uint64_t)first << 32 | second;
    return true;
}

static bool handle(struct input *input) {
    uint32_t length;
    if (!take32(input, &length) || length != 1 || input->left < 1 || *input->bytes != 'f')
        return false;
    input->bytes++;
    input->left--;
    return true;
}

static void put32(struct packet *p, uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8)
        p->bytes[p->end++] = (unsigned char)(value >> shift);
}

static void put64(struct packet *p, uint64_t value) {
    put32(p, (uint32_t)(value >> 32));
    put32(p, (uint32_t)value);
}

static void start(struct packet *p, unsigned char kind, uint32_t id) {
    p->end = 4;
    p->bytes[p->end++] = kind;
    put32(p, id);
}

static bool send_packet(struct packet *p) {
    size_t count = p->end;
    p->end = 0;
    put32(p, (uint32_t)(count - 4));
    return exact_io(STDOUT_FILENO, p->bytes, count, true);
}

static bool status(uint32_t id, uint32_t value) {
    struct packet p;
    start(&p, STATUS, id);
    put32(&p, value);
    put32(&p, 0); /* empty status text and language */
    put32(&p, 0);
    return send_packet(&p);
}

static int64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static bool event(const struct session *s, const char *kind, uint64_t offset, unsigned count) {
    char line[160];
    int64_t stamp = milliseconds();
    if (stamp < 0) return false;
    int length = snprintf(line, sizeof(line), "%s %u %s %" PRIu64 " %u %" PRId64 "\n",
                          s->name, s->attempt, kind, offset, count, stamp);
    return length > 0 && (size_t)length < sizeof(line)
        && write(s->trace, line, (size_t)length) == length;
}

static const char *select_path(struct input input, bool *exact) {
    uint32_t length;
    if (!take32(&input, &length) || length > input.left) return NULL;
    *exact = input.left == length;
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        char path[100];
        int size = snprintf(path, sizeof(path), "/retry-input/%s", cases[index]);
        if (size > 0 && (size_t)size < sizeof(path) && (uint32_t)size == length
                && memcmp(input.bytes, path, length) == 0) return cases[index];
    }
    return NULL;
}

static int open_source(const char *name) {
    char path[sizeof(INPUT) + 32];
    int size = snprintf(path, sizeof(path), INPUT "%s", name);
    if (size < 1 || (size_t)size >= sizeof(path)) return -1;
    int file = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (file < 0) return -1;
    struct stat info;
    if (fstat(file, &info) != 0 || !S_ISREG(info.st_mode) || info.st_nlink != 1
            || info.st_size != SOURCE_BYTES || (info.st_mode & 0777) != 0444) {
        close(file);
        return -1;
    }
    return file;
}

static bool attrs(uint32_t id, int file) {
    struct stat info;
    if (fstat(file, &info) != 0 || info.st_mtime < 0 || info.st_mtime > UINT32_MAX
            || info.st_atime < 0 || info.st_atime > UINT32_MAX) return false;
    struct packet p;
    start(&p, ATTRS, id);
    put32(&p, 13); /* size, mode, access/modification times */
    put64(&p, (uint64_t)info.st_size);
    put32(&p, (uint32_t)info.st_mode);
    put32(&p, (uint32_t)info.st_atime);
    put32(&p, (uint32_t)info.st_mtime);
    return send_packet(&p);
}

static unsigned occupy(const char *name) {
    char path[sizeof(STATE) + 48];
    for (unsigned attempt = 1; attempt <= 4; attempt++) {
        int size = snprintf(path, sizeof(path), STATE "%s.%u", name, attempt);
        if (size < 1 || (size_t)size >= sizeof(path)) return 0;
        int marker = open(path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (marker >= 0) {
            close(marker);
            return attempt;
        }
        if (errno != EEXIST) return 0;
    }
    return 0;
}

/* Only the fixture operator can release a selected reply. EOF is separately observed. */
static int wait_reply(bool release_allowed) {
    int64_t now = milliseconds();
    if (now < 0) return -1;
    int64_t deadline = now + WAIT_MS;
    for (; now >= 0 && now < deadline; now = milliseconds()) {
        if (release_allowed) {
            struct stat trigger;
            if (lstat(CONTROL "release-redial", &trigger) == 0) {
                if (!S_ISREG(trigger.st_mode) || trigger.st_size != 0) return -1;
                return 1;
            }
            if (errno != ENOENT) return -1;
        }
        struct pollfd stream = {.fd = STDIN_FILENO, .events = POLLIN};
        int ready = poll(&stream, 1, 20);
        if (ready < 0 && errno != EINTR) return -1;
        if (ready > 0 && stream.revents) {
            unsigned char next;
            ssize_t count = read(STDIN_FILENO, &next, 1);
            if (count == 0) return 0;
            if (count < 0 && errno == EINTR) continue;
            return -1; /* extra SFTP traffic during the withheld request is unexpected */
        }
    }
    return -1;
}

/* 0 is orderly transport closure, 1 is a response, -1 is a fixture failure. */
static int read_file(struct session *s, struct input input, uint32_t id) {
    uint64_t offset;
    uint32_t length;
    if (s->file < 0 || !handle(&input) || !take64(&input, &offset) || !take32(&input, &length)
            || input.left || offset > SOURCE_BYTES || length == 0 || length > MAX_READ) return -1;
    if (!event(s, "read", offset, length)) return -1;
    bool redial = strcmp(s->name, "redial") == 0;
    bool second_start = redial && s->attempt == 2 && offset == 0;
    bool withhold = offset == FAULT_OFFSET && (!redial || s->attempt == 1);
    if (second_start || withhold) {
        if (!event(s, second_start ? "new-zero-held" : "timeout-held", offset, length)) return -1;
        int observed = wait_reply(second_start);
        if (observed == 0)
            return event(s, "transport-closed", offset, length) ? 0 : -1;
        if (observed < 0) {
            (void)event(s, "peer-budget", offset, length);
            return -1;
        }
        if (!event(s, "released", offset, length)) return -1;
    }
    if (offset == SOURCE_BYTES)
        return event(s, "eof", offset, length) && status(id, 1) ? 1 : -1;
    size_t count = length;
    if (count > SOURCE_BYTES - offset) count = (size_t)(SOURCE_BYTES - offset);
    struct packet p;
    start(&p, DATA, id);
    put32(&p, (uint32_t)count);
    if (pread(s->file, p.bytes + p.end, count, (off_t)offset) != (ssize_t)count) return -1;
    p.end += count;
    return send_packet(&p) ? 1 : -1;
}

static int request(struct session *s, unsigned kind, uint32_t id, struct input input) {
    if (kind == READ) return read_file(s, input, id);
    if (kind == FSTAT)
        return s->file >= 0 && handle(&input) && !input.left && event(s, "fstat", 0, 0)
            && attrs(id, s->file) ? 1 : -1;
    if (kind == CLOSE) {
        if (s->file < 0 || !handle(&input) || input.left || close(s->file) != 0) return -1;
        s->file = -1;
        return event(s, "close", 0, 0) && status(id, 0) ? 1 : -1;
    }
    if (kind != OPEN && kind != STAT && kind != LSTAT)
        return status(id, 8) ? 1 : -1; /* operation unsupported */
    bool exact;
    const char *name = select_path(input, &exact);
    if (name == NULL || (s->name != NULL && s->name != name))
        return status(id, 2) ? 1 : -1;
    if (kind == OPEN) {
        uint32_t length, flags, attributes;
        if (s->name != NULL || !take32(&input, &length) || length > input.left) return -1;
        input.bytes += length;
        input.left -= length;
        if (!take32(&input, &flags) || !take32(&input, &attributes) || input.left
                || flags != 1 || attributes != 0) return -1;
        s->attempt = occupy(name);
        if (s->attempt == 0) return -1;
        s->file = open_source(name);
        if (s->file < 0) return -1;
        s->name = name;
        if (!event(s, "open", 0, 0)) return -1;
        struct packet p;
        start(&p, HANDLE, id);
        put32(&p, 1);
        p.bytes[p.end++] = 'f';
        return send_packet(&p) ? 1 : -1;
    }
    if (!exact) return -1;
    int named = open_source(name);
    if (named < 0) return -1;
    bool result = (s->name == NULL || event(s, "lstat", 0, 0)) && attrs(id, named);
    close(named);
    return result ? 1 : -1;
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "-c") != 0 || strcmp(argv[2], COMMAND) != 0) return 2;
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) return 2;
    alarm(120);
    struct session s = {
        .file = -1,
        .trace = open(STATE "events", O_WRONLY | O_APPEND | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC),
    };
    struct stat trace;
    if (s.trace < 0 || fstat(s.trace, &trace) != 0 || !S_ISREG(trace.st_mode)
            || trace.st_nlink != 1 || trace.st_size > 65536) return 2;
    for (uint32_t index = 0; index < MAX_REQUESTS; index++) {
        unsigned char header[4], bytes[MAX_REQUEST];
        if (!exact_io(STDIN_FILENO, header, sizeof(header), false)) return index ? 0 : 2;
        struct input input = {header, sizeof(header)};
        uint32_t size, id;
        if (!take32(&input, &size) || size < 5 || size > sizeof(bytes)
                || !exact_io(STDIN_FILENO, bytes, size, false)) return 2;
        input = (struct input){bytes + 1, size - 1};
        if (!take32(&input, &id)) return 2;
        if (index == 0) {
            if (bytes[0] != INIT || id != 3 || input.left) return 2;
            struct packet p;
            start(&p, VERSION, 3);
            if (!send_packet(&p)) return 2;
            continue;
        }
        if (id != index) return 2;
        int result = request(&s, bytes[0], id, input);
        if (result <= 0) return result == 0 ? 0 : 2;
    }
    return 2;
}
