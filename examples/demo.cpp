#include "../include/libtagalloc.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

#include <unistd.h> // getpid

static constexpr uint32_t tag4(char a, char b, char c, char d) {
  // Poolmon-style: little-endian bytes (lowest byte first)
  return (static_cast<uint32_t>(static_cast<unsigned char>(a)) << 0) |
         (static_cast<uint32_t>(static_cast<unsigned char>(b)) << 8) |
         (static_cast<uint32_t>(static_cast<unsigned char>(c)) << 16) |
         (static_cast<uint32_t>(static_cast<unsigned char>(d)) << 24);
}

int main() {
  const int pid = static_cast<int>(getpid());
  std::printf("tagalloc-demo-cpp pid=%d\n", pid);

  const uint32_t tags[] = {
      tag4('A', 'B', 'C', 'D'),
      tag4('W', 'X', 'Y', 'Z'),
      tag4('4', '3', '2', '1'),
  };
  const size_t sizes[] = {64, 256, 4096};

  uint64_t iter = 0;
  while (true) {
    for (size_t i = 0; i < (sizeof(tags) / sizeof(tags[0])); i++) {
      const uint32_t tag = tags[i];
      const size_t size = sizes[i % (sizeof(sizes) / sizeof(sizes[0]))];

      void *p = tagalloc_alloc(tag, size);
      if (!p) {
        std::fprintf(stderr, "tagalloc_alloc failed\n");
        return 1;
      }

      const unsigned char fill = static_cast<unsigned char>(iter);
      std::memset(p, fill, size < 32 ? size : 32);
      tagalloc_free(p);
    }

    iter++;
    usleep(100 * 1000);
  }

  return 0;
}
