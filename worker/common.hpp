#pragma once

#define IBV_WR_SECURE_WRITE 1
#define IBV_WR_SECURE_READ 2
#define IBV_WR_SECURE_SEND 3

#define IBV_ETH (1 << 4)
#define IBV_WR_SECURE_MEMORY (1 << 5)
#define IBV_WC_SECURE_FAILURE (1 << 6)
#define IBV_WR_SECURE_SIGNALED (1 << 7)

#define ADDR_MASK (0xFFFFFFFFFFFFFUL)
#define VIRT_ADDR (((uint64_t)1) << 54)
#define DMA (((uint64_t)1) << 55)

#define IBV_WRID_METADATA_MASK 0xFF
#define IBV_WRID_REQUEST_MASK 0b111
#define IBV_WRID_METADATA_BITS 8

#define IBV_WC_OFFSET 12
#define IBV_WC_SECURE_WRITE (IBV_WR_SECURE_WRITE + IBV_WC_OFFSET)
#define IBV_WC_SECURE_READ (IBV_WR_SECURE_READ + IBV_WC_OFFSET)
#define IBV_WC_SECURE_SEND (IBV_WR_SECURE_SEND + IBV_WC_OFFSET)

static_assert((1 << IBV_WRID_METADATA_BITS) - 1 == IBV_WRID_METADATA_MASK,
              " IBV_WRID_METADATA error");
static_assert((IBV_WRID_METADATA_MASK & IBV_WR_SECURE_WRITE) ==
                  IBV_WR_SECURE_WRITE,
              " IBV_WR_SECURE_WRITE should fit into IBV_WRID_METADATA_MASK");
static_assert((IBV_WRID_METADATA_MASK & IBV_WR_SECURE_READ) ==
                  IBV_WR_SECURE_READ,
              " IBV_WR_SECURE_READ should fit into IBV_WRID_METADATA_MASK");
static_assert((IBV_WRID_METADATA_MASK & IBV_WR_SECURE_SIGNALED) ==
                  IBV_WR_SECURE_SIGNALED,
              " IBV_WR_SECURE_SIGNALED should fit into IBV_WRID_METADATA_MASK");
static_assert(
    (IBV_WC_SECURE_READ & IBV_WR_SECURE_SIGNALED) == 0,
    " IBV_WC_SECURE_READ should not intersect with  IBV_WR_SECURE_SIGNALED");

static_assert((IBV_WRID_METADATA_MASK & IBV_WC_SECURE_FAILURE) ==
                  IBV_WC_SECURE_FAILURE,
              " IBV_WC_SECURE_FAILURE should fit into IBV_WRID_METADATA_MASK");
static_assert(
    (IBV_WC_SECURE_READ & IBV_WC_SECURE_FAILURE) == 0,
    " IBV_WC_SECURE_READ should not intersect with  IBV_WC_SECURE_FAILURE");

#define DISCONNECT 99

typedef struct {
  uint32_t qpn;  // :24
  uint32_t macsize : 8;
  uint32_t psn : 24;
} transport_header_t;

static_assert(sizeof(transport_header_t) == 8, " transport_header_t ");

typedef struct {
  uint64_t remote;
  uint32_t rkey;
} write_header_t;

typedef struct {
  uint64_t from;
  uint64_t to;
  uint32_t from_rkey;
  uint32_t to_rkey;
  uint32_t length;
  uint32_t padding;
} read_header_t;

typedef struct {
  uint64_t addr;
  uint32_t rkey;
  uint32_t length;
} ext_transport_header_t;
