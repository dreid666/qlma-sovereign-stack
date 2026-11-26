#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fcntl>
#include <iostream>
#include <sys/mman.h>
#include <unistd>

constexpr std::size_t RING_SIZE = 1024;
constexpr const char* SHM_NAME = "/qlma-telemetry-example";

struct alignas(64) Frame {
    double real[18]{};
    double imag[18]{};
    std::uint32_t trust_flag{0};
    std::uint32_t sequence{0};
};

struct alignas(64) SharedState {
    alignas(64) std::atomic<std::uint32_t> head{0};
    alignas(64) std::atomic<std::uint32_t> tail{0};
    alignas(64) Frame frames[RING_SIZE]{};
};

static_assert(RING_SIZE > 0);
static_assert((RING_SIZE & (RING_SIZE - 1)) == 0);

int main() {
    shm_unlink(SHM_NAME);
    int fd = shm_open(SHM_NAME, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd == -1) {
        std::perror("shm_open");
        return 1;
    }

    if (ftruncate(fd, static_cast<off_t>(sizeof(SharedState))) == -1) {
        std::perror("ftruncate");
        close(fd);
        shm_unlink(SHM_NAME);
        return 1;
    }

    void* ptr = mmap(nullptr, sizeof(SharedState), PROT_READ | PROT_WRITE,
                     MAP_SHARED, fd, 0);
    close(fd);
    if (ptr == MAP_FAILED) {
        std::perror("mmap");
        shm_unlink(SHM_NAME);
        return 1;
    }

    auto* shm = new (ptr) SharedState;

    for (std::uint32_t i = 0; i < 10; ++i) {
        std::uint32_t head = shm->head.load(std::memory_order_relaxed);
        std::uint32_t tail = shm->tail.load(std::memory_order_acquire);
        if (head - tail >= RING_SIZE) {
            std::cerr << "ring full\n";
            munmap(ptr, sizeof(SharedState));
            shm_unlink(SHM_NAME);
            return 1;
        }

        Frame& frame = shm->frames[head & (RING_SIZE - 1)];
        frame.sequence = i;
        frame.trust_flag = 1;
        for (std::size_t lane = 0; lane < 18; ++lane) {
            frame.real[lane] = static_cast<double>(i);
            frame.imag[lane] = 0.0;
        }
        shm->head.store(head + 1, std::memory_order_release);

        const Frame& observed = shm->frames[tail & (RING_SIZE - 1)];
        if (observed.trust_flag != 1) {
            std::cerr << "untrusted frame rejected\n";
            munmap(ptr, sizeof(SharedState));
            shm_unlink(SHM_NAME);
            return 1;
        }
    }

    shm->tail.store(10, std::memory_order_release);
    if (munmap(ptr, sizeof(SharedState)) == -1) {
        std::perror("munmap");
        shm_unlink(SHM_NAME);
        return 1;
    }
    if (shm_unlink(SHM_NAME) == -1) {
        std::perror("shm_unlink");
        return 1;
    }
    return 0;
}
