/*
 * @Author: phd 1010990249@qq.com
 * @Date: 2023-04-19 02:14:39
 * @LastEditors: phd 1010990249@qq.com
 * @LastEditTime: 2023-04-26 01:45:30
 * @FilePath: /sRDMA/worker/CircularBuf.hpp
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
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
//size < mr.length;超过时直接从0开始
  inline char* get(uint32_t size) {
    if (size + current > mr.length) {
      current = 0;
    }
    uint32_t offset = current; //偏移
    current += size; //更新当前偏移
    return (char*)mr.addr + offset;
  }

  inline uint32_t lkey() const { return mr.lkey; }
};