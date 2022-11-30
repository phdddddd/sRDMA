#pragma once

#include <infiniband/verbs.h>

// it is not thread safe
class circular_buf_t {
  struct ibv_mr mr;
  uint32_t current;

 public:
  circular_buf_t() {}

  circular_buf_t(struct ibv_mr mr) : mr(mr), current(0) {
    // empty
  }

  inline char* get(uint32_t size) {
    if (size + current > mr.length) {
      current = 0;
    }
    uint32_t offset = current;
    current += size;
    return (char*)mr.addr + offset;
  }

  inline uint32_t lkey() const { return mr.lkey; }
};