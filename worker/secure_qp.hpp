#pragma once

#include <vector>
#include "../rdma_com/rdma_com.hpp"
#include "../security/security.hpp"
#include "CircularBuf.hpp"
#include "common.hpp"

class SequreQP {
  Connection* dma_con;
  circular_buf_t circular_buf;  // it is not thread safe

 public:
  /**
   * @description: 发送memkey和pdkey
   * @return {*}
   */ 
  SequreQP(Connection* dma_con, const unsigned char* pdkey = NULL,
           const unsigned char* memkey = NULL, uint32_t cir_buf_size = 4096)
      : dma_con(dma_con) {
    char* buf = (char*)aligned_alloc(4096, cir_buf_size);
    struct ibv_mr* mr =
        ibv_reg_mr(this->dma_con->id->pd, buf, cir_buf_size,
                   IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE |
                       IBV_ACCESS_REMOTE_READ);

    assert(mr != NULL);

    this->circular_buf = circular_buf_t(*mr);

    uint32_t length =
        sizeof(init_attribure_t) + sizeof(secure_attribure_header_t);

    secure_attribure_header_t* h =
        (secure_attribure_header_t*)this->circular_buf.get(length);
    h->type = INIT;

    init_attribure_t* s =
        (init_attribure_t*)((char*)h + sizeof(secure_attribure_header_t));

    s->drkey = pdkey != NULL;
    /*  -------------------------   -----------------   
      | secure_attribure_header_t | init_attribure_t |
      h ------------------------- s ----------------- 
     */
    if (pdkey != NULL) {
      memcpy(s->pdkey, pdkey, KDFKEYSIZE);
    }

    s->withmemkey = (memkey != NULL);

    if (memkey != NULL) {
      text(log_fp, "With memory protection \n");
      memcpy(s->memkey, memkey, KDFKEYSIZE);
    }
//send secure_attribure_header_t and init_attribure_t
    this->dma_con->send_signaled(0, (char*)h, this->circular_buf.lkey(),
                                 length);

    struct ibv_wc wc;
    while (!this->dma_con->send_check(&wc)) {
      // empty
    }
  }

  uint32_t GetQPN() { return this->dma_con->GetQPN(); }

  void modify_to_RTR(uint32_t remote_psn, uint32_t dest_qp_num,
                     ibv_qp_crypto cryptoname = ibv_qp_crypto::IBV_NO_SECURITY,
                     const unsigned char* key = NULL, uint32_t keysize = 0) {
    uint32_t length =
        sizeof(rtr_attribure_t) + sizeof(secure_attribure_header_t);

    secure_attribure_header_t* h =
        (secure_attribure_header_t*)this->circular_buf.get(length);
    h->type = RTR;

    rtr_attribure_t* s =
        (rtr_attribure_t*)((char*)h + sizeof(secure_attribure_header_t));
    s->cryptoname = cryptoname;
    s->remote_psn = remote_psn;
    s->dest_qp_num = dest_qp_num;
    if (keysize) {
      memcpy(s->key, key, keysize);
    }

    this->dma_con->send_signaled(0, (char*)h, this->circular_buf.lkey(),
                                 length);

    struct ibv_wc wc;
    while (!this->dma_con->send_check(&wc)) {
      // empty
    };
  }

  void modify_to_RTS(uint32_t mypsn) {
    uint32_t length =
        sizeof(rts_attribure_t) + sizeof(secure_attribure_header_t);

    secure_attribure_header_t* h =
        (secure_attribure_header_t*)this->circular_buf.get(length);
    h->type = RTS;

    rts_attribure_t* s =
        (rts_attribure_t*)((char*)h + sizeof(secure_attribure_header_t));
    s->mypsn = mypsn;

    this->dma_con->send_signaled(0, (char*)h, this->circular_buf.lkey(),
                                 length);

    struct ibv_wc wc;
    while (!this->dma_con->send_check(&wc)) {
      // empty
    }
  }

  ~SequreQP() {
    // delete dma_con;
    // poll_t.join();
  }

  int poll_send_cq(struct ibv_wc* wc) {
    int ret = ibv_poll_cq(dma_con->id->qp->send_cq, 1, wc);

    wc->opcode =
        (enum ibv_wc_opcode)(uint32_t)(wc->wr_id & IBV_WRID_METADATA_MASK);
    wc->wr_id = (wc->wr_id >> IBV_WRID_METADATA_BITS);

    return ret;
  }

  int poll_recv_cq(struct ibv_wc* wc) {
    int ret = ibv_poll_cq(dma_con->id->qp->recv_cq, 1, wc);

    if (ret > 0 && (wc->wc_flags == IBV_WC_WITH_IMM)) {
      text(log_fp, "[shadow_poll_recv_cq] Packet has been intercepted \n");

      // here we can change WC to SECURE_READ or SECURE_WRITE
      wc->opcode = (enum ibv_wc_opcode)(uint32_t)(
          (wc->imm_data & IBV_WRID_REQUEST_MASK) + IBV_WC_OFFSET);
      wc->wr_id = (uint64_t)(wc->imm_data >> IBV_WRID_METADATA_BITS);
    }

    return ret;
  }

  void post_recv(uint64_t buf_addr, uint32_t length, uint32_t lkey,
                 uint64_t wr_id) {
    struct ibv_sge sge;

    sge.addr = buf_addr;
    sge.length = length;
    sge.lkey = lkey;

    struct ibv_recv_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    int ret = ibv_post_recv(dma_con->id->qp, &wr, &bad);
    if (ret) {
      perror("\t[post_recv] secure qp ibv_post_recv");
      return;
    }
  }

  void post_recv(struct ibv_mr* mr, uint64_t wr_id) {
    post_recv((uint64_t)mr->addr, mr->length, mr->lkey, wr_id);
  }

  struct ibv_mr* reg_mem(void* mem, uint32_t length, bool withmemprot = false) {
    struct ibv_mr* mr = dma_con->reg_mem(mem, length);
    if (withmemprot) {
      secure_attribure_header_t* h = (secure_attribure_header_t*)mr->addr;
      h->type = MEMORY_REG;
      mem_attribure_t* s =
          (mem_attribure_t*)((char*)mr->addr +
                             sizeof(secure_attribure_header_t));

      *s = {(uint64_t)mr->addr, (uint32_t)mr->length, mr->rkey};

      uint32_t length =
          sizeof(mem_attribure_t) + sizeof(secure_attribure_header_t);

      this->dma_con->send_signaled(0, (char*)(mr->addr), mr->lkey, length);

      struct ibv_wc wc;
      while (!this->dma_con->send_check(&wc)) {
        // empty
      }
    }
    return mr;
  }

  struct ibv_mr* reg_mem(uint32_t length, bool withmemprot = false) {
    char* buf = (char*)aligned_alloc(4096, length);
    struct ibv_mr* mr = dma_con->reg_mem(buf, length);
    if (withmemprot) {
      secure_attribure_header_t* h = (secure_attribure_header_t*)mr->addr;
      h->type = MEMORY_REG;
      mem_attribure_t* s =
          (mem_attribure_t*)((char*)mr->addr +
                             sizeof(secure_attribure_header_t));

      *s = {(uint64_t)mr->addr, (uint32_t)mr->length, mr->rkey};

      uint32_t length =
          sizeof(mem_attribure_t) + sizeof(secure_attribure_header_t);

      this->dma_con->send_signaled(0, (char*)(mr->addr), mr->lkey, length);

      struct ibv_wc wc;
      while (!this->dma_con->send_check(&wc)) {
        // empty
      }
    }
    return mr;
  }

  void reg_mem(struct ibv_mr* mr) {
    uint32_t length =
        sizeof(mem_attribure_t) + sizeof(secure_attribure_header_t);

    secure_attribure_header_t* h =
        (secure_attribure_header_t*)this->circular_buf.get(length);
    h->type = MEMORY_REG;
    mem_attribure_t* s =
        (mem_attribure_t*)((char*)h + sizeof(secure_attribure_header_t));

    *s = {(uint64_t)mr->addr, (uint32_t)mr->length, mr->rkey};
    // send shit

    this->dma_con->send_signaled(0, (char*)(h), this->circular_buf.lkey(),
                                 length);

    struct ibv_wc wc;
    while (!this->dma_con->send_check(&wc)) {
      // empty
    }
  }

  void DeregisterLocalMemory(struct ibv_mr* mr) { dma_con->dereg_mem(mr); }

  inline int Write(uint32_t wr_id, uint64_t local, uint32_t lkey,
                   uint32_t length, uint64_t remote, uint32_t rkey,
                   bool signaled, region_t* region = NULL) {
    struct ibv_sge sge[2];

    uint32_t header_length =
        sizeof(write_header_t) + (region == NULL ? 0 : sizeof(region_t));

    text(log_fp, "\t\t\t[Write] additional header is %u \n", header_length);

    unsigned char* header =
        (unsigned char*)this->circular_buf.get(header_length);

    // Fill write header
    write_header_t* wh = (write_header_t*)header;
    wh->remote = remote;
    wh->rkey = rkey;

    if (region) {
      memcpy(header + sizeof(write_header_t), region, sizeof(region_t));
    }

    // set a header
    sge[0].addr = (uint64_t)(uintptr_t)header;
    sge[0].length = header_length;
    sge[0].lkey = this->circular_buf.lkey();

    sge[1].addr = local;
    sge[1].length = length;
    sge[1].lkey = lkey;

    struct ibv_send_wr wr, *bad;

    wr.wr_id = 0;
    wr.next = NULL;
    wr.sg_list = &sge[0];
    wr.num_sge = 2;
    wr.opcode = IBV_WR_SEND_WITH_IMM;
    wr.imm_data = (wr_id << IBV_WRID_METADATA_BITS) | IBV_WR_SECURE_WRITE;
    wr.send_flags = 0;

    if (region) {
      wr.imm_data |= IBV_WR_SECURE_MEMORY;
    }

    if (signaled) {
      wr.send_flags = IBV_SEND_SIGNALED;
      wr.imm_data |= IBV_WR_SECURE_SIGNALED;
    }

    return ibv_post_send(this->dma_con->id->qp, &wr, &bad);
  }

  inline int Send(uint32_t wr_id, uint64_t local, uint32_t lkey,
                  uint32_t length, bool signaled) {
    struct ibv_sge sge;

    sge.addr = local;
    sge.length = length;
    sge.lkey = lkey;

    struct ibv_send_wr wr, *bad;

    wr.wr_id = 0;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND_WITH_IMM;
    wr.imm_data = (wr_id << IBV_WRID_METADATA_BITS) | IBV_WR_SECURE_SEND;
    wr.send_flags = 0;

    if (signaled) {
      wr.send_flags = IBV_SEND_SIGNALED;
    }

    return ibv_post_send(this->dma_con->id->qp, &wr, &bad);
  }

  inline int Send(uint32_t wr_id, struct ibv_sge* sge, bool signaled) {
    struct ibv_send_wr wr, *bad;

    wr.wr_id = 0;
    wr.next = NULL;
    wr.sg_list = sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND_WITH_IMM;
    wr.imm_data = (wr_id << IBV_WRID_METADATA_BITS) | IBV_WR_SECURE_SEND;
    wr.send_flags = 0;

    if (signaled) {
      wr.send_flags = IBV_SEND_SIGNALED;
    }

    return ibv_post_send(this->dma_con->id->qp, &wr, &bad);
  }

  inline int Read(uint32_t wr_id, uint64_t local, uint32_t local_rkey,
                  uint32_t length, uint64_t remote, uint32_t remote_rkey,
                  bool signaled, region_t* region = NULL) {
    struct ibv_sge sge;

    uint32_t header_length =
        sizeof(read_header_t) + (region == NULL ? 0 : sizeof(region_t));

    text(log_fp, "\t\t\t[Read] additional header is %u \n", header_length);

    unsigned char* header =
        (unsigned char*)this->circular_buf.get(header_length);

    read_header_t* rh = (read_header_t*)(header);
    rh->from = remote;
    rh->from_rkey = remote_rkey;
    rh->to = local;
    rh->to_rkey = local_rkey;
    rh->length = length;

    if (region) {
      memcpy(header + sizeof(read_header_t), region, sizeof(region_t));
    }

    // set a header
    sge.addr = (uint64_t)(uintptr_t)rh;
    sge.length = header_length;
    sge.lkey = this->circular_buf.lkey();

    struct ibv_send_wr wr, *bad;

    wr.wr_id = 0;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND_WITH_IMM;
    wr.imm_data = (wr_id << IBV_WRID_METADATA_BITS) | IBV_WR_SECURE_READ;
    wr.send_flags = 0;

    if (region) {
      wr.imm_data |= IBV_WR_SECURE_MEMORY;
    }

    if (signaled) {
      wr.send_flags = IBV_SEND_SIGNALED;
      wr.imm_data |= IBV_WR_SECURE_SIGNALED;
    }
    return ibv_post_send(this->dma_con->id->qp, &wr, &bad);
  }
};
