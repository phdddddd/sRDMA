#pragma once
#include <infiniband/verbs.h>
#include <algorithm>
#include <atomic>
#include <boost/pool/object_pool.hpp>
#include <queue>
#include <unordered_map>
#include <utility>
#include <vector>
#include "../rdma_com/rdma_com.hpp"
#include "../security/security.hpp"
#include "../thread/thread.hpp"
#include "../utilities/readerwriterqueue.h"
#include "CircularBuf.hpp"
#include "common.hpp"
#include "generic_worker.hpp"

#define POLL_BATCH_SIZE 8U

#define HEADER_RESERVED 128U

using namespace moodycamel;

struct secure_connection_t {
  Connection* recvcon;
  Connection* sendcon;
  ibv_secure_ctx* secctx;
  //   bool drkey;
  uint32_t dest_qp_num;
  //  secure_pd_t* pd;
};

struct write_t {
  Connection* con;
  uint32_t imm_data;
};

struct read_t {
  Connection* con;
  uint64_t addr;
  uint32_t imm_data;
  uint32_t rkey;
};

class SecureWorker : public GenericWorker {
  struct SecureReadWriteCtx {
    secure_connection_t* seccon;
    uint32_t imm_data;
    struct ibv_mr* mr;

    uint64_t addr;
    uint32_t rkey;
    uint32_t length;

    uint32_t payloadoffset;

    SecureReadWriteCtx(secure_connection_t* seccon, uint32_t imm_data,
                       struct ibv_mr* mr, uint32_t payloadoffset)
        : seccon(seccon),
          imm_data(imm_data),
          mr(mr),
          payloadoffset(payloadoffset) {
      // empty
    }

    static inline void Set(SecureReadWriteCtx* ctx, secure_connection_t* seccon,
                           uint32_t imm_data, struct ibv_mr* mr,
                           uint64_t addr = 0, uint32_t rkey = 0,
                           uint32_t length = 0, uint32_t payloadoffset = 0) {
      ctx->seccon = seccon;
      ctx->imm_data = imm_data;
      ctx->mr = mr;
      ctx->addr = addr;
      ctx->rkey = rkey;
      ctx->length = length;
      ctx->payloadoffset = payloadoffset;
    }
  };

 public:
  SecureWorker(int id, IOWatcher* w, Connection* niccon, Connection* dmacon,
               uint32_t packetsize)
      : id(id),
        local_io_watcher(w),
        niccon(niccon),
        dmacon(dmacon),
        drkey(false) {
    {
      //先划分一整块内存注册mr，再按照packetsize细分
      uint32_t allocate = niccon->max_recv_size *
                          (packetsize + HEADER_RESERVED + HEADER_RESERVED);
      char* buf = (char*)aligned_alloc(4096, allocate);
      if (buf == NULL) {
        printf("[Error] Not enough memory to allocate  %u bytes \n", allocate);
        exit(1);
      }
      struct ibv_mr* originalmr = niccon->reg_mem(buf, allocate);

      struct ibv_mr* mr =
          (struct ibv_mr*)malloc(sizeof(struct ibv_mr) * niccon->max_recv_size);

      for (uint32_t i = 0; i < niccon->max_recv_size; i++) {
        mr[i] = *originalmr;
        mr[i].addr = (char*)(originalmr->addr) +
                     (packetsize + HEADER_RESERVED + HEADER_RESERVED) * i +
                     HEADER_RESERVED;
        mr[i].length = (packetsize + HEADER_RESERVED);

        niccon->post_recv((uint64_t)&mr[i], &mr[i]);
      }
    }

    {
      uint32_t allocate = dmacon->max_recv_size *
                          (packetsize + HEADER_RESERVED + HEADER_RESERVED);
      char* buf = (char*)aligned_alloc(4096, allocate);
      if (buf == NULL) {
        printf("[Error] Not enough memory to allocate  %u bytes \n", allocate);
        exit(1);
      }
      struct ibv_mr* originalmr = dmacon->reg_mem(buf, allocate);

      struct ibv_mr* mr =
          (struct ibv_mr*)malloc(sizeof(struct ibv_mr) * dmacon->max_recv_size);

      for (uint32_t i = 0; i < dmacon->max_recv_size; i++) {
        mr[i] = *originalmr;
        mr[i].addr = (char*)(originalmr->addr) +
                     (packetsize + HEADER_RESERVED + HEADER_RESERVED) * i +
                     HEADER_RESERVED;
        mr[i].length = (packetsize + HEADER_RESERVED);

        dmacon->post_recv((uint64_t)&mr[i], &mr[i]);
      }
    }

    this->tempbuf = (unsigned char*)malloc(512 / 8);  // 512 bits
    this->derived_key = (unsigned char*)malloc(MAX_KEY_LENGTH);
    this->pdmemkey = (unsigned char*)malloc(KDFKEYSIZE);
    this->derived_mem_key = (unsigned char*)malloc(KDFKEYSIZE);
    memset(this->tempbuf, 0, 512 / 8);
    memset(this->derived_key, 0, MAX_KEY_LENGTH);
    memset(this->pdmemkey, 0, KDFKEYSIZE);
    memset(this->derived_mem_key, 0, KDFKEYSIZE);

    this->pending_dma_req = 0;
    this->max_pending_dma_req = dmacon->send_size();
    this->used_buffers = 0;
    this->pending_req = 0;

    struct ibv_mr* mr = niccon->reg_mem(4096 * 10);

    assert(mr != NULL);

    this->circular_buf = circular_buf_t(*mr);
  };

  ~SecureWorker() {
    // empty
  }

  void main_cb() override;
  void sometimes_cb() override;

 protected:
  void PollWork();
  void PollRequest();
  void PollDMASendCompletion();

  void PollClientSendCompletion();
  void ProcessRecvRequest(struct ibv_wc* wc);
  void ProcessSendRequest(struct ibv_wc* wc);

  void ProcessDMACompletion(struct ibv_wc* wc);

  void ProcessClientCompletion(struct ibv_wc* wc);

  int SecureSend(uint64_t wr_id, uint32_t imm_data, uint32_t originallength,
                 secure_connection_t* seccon, struct ibv_mr* mr);
  int SecureWrite(uint64_t wr_id, uint32_t imm_data, uint32_t originallength,
                  secure_connection_t* seccon, struct ibv_mr* mr);
  int SecureRead(uint32_t imm_data, secure_connection_t* seccon,
                 struct ibv_mr* mr);

  int SecureWriteReply(uint32_t imm_data, secure_connection_t* seccon);
  int SecureReadReply(uint64_t wr_id, uint32_t imm_data,
                      uint32_t originallength, secure_connection_t* seccon,
                      struct ibv_mr* mr);

  void PollDMAControlRequest();
  void ProcessDMAControlRequest(struct ibv_wc* wc);

  const int id;

  IOWatcher* const local_io_watcher;

  Connection* niccon;
  Connection* dmacon;

  //   std::map<uint32_t, Connection*>  qpn_to_connection;
//map管理secure_connections,qpn检索        
  std::map<uint32_t, secure_connection_t*> secure_connections;

  boost::object_pool<SecureReadWriteCtx> MemPoolSecCtx;

  unsigned char* tempbuf;
  bool drkey;  //question:drkey
  ibv_kdf_ctx kdfctx;
  unsigned char* master_key;
  unsigned char* derived_key;

  ibv_kdf_ctx memkdf;
  unsigned char* pdmemkey;
  unsigned char* derived_mem_key;
  std::unordered_map<uint32_t, mem_attribure_t> memlookup;

  // statistics
  uint32_t pending_dma_req;//剩余的dma req
  uint32_t used_buffers;
  uint32_t pending_req;
  uint32_t max_pending_dma_req;

  circular_buf_t circular_buf;  // it is not thread safe

  std::queue<read_t> read_queue;
  std::queue<write_t> write_queue;

  // uint32_t packetsize;
};

void SecureWorker::main_cb() {
  PollRequest();
  PollDMASendCompletion();
  PollClientSendCompletion();
  PollDMAControlRequest();
}

void SecureWorker::sometimes_cb() {
  //    printf("%u %u %u\n", pending_dma_req, used_buffers,pending_req );
}


/**
 * @description: polling nic connection's RDMA receive requests and processing them.But only one wc every time. 
 * @return {*}
 */
inline void SecureWorker::PollRequest() {
  struct ibv_wc pool_wc[POLL_BATCH_SIZE];

  uint32_t topoll = std::min(10 - this->pending_dma_req, 1U); //每次处理一个req
  if (topoll) {
    int req = niccon->recv_check(&pool_wc[0], topoll);

    if (req) {
      used_buffers += req;

      text(log_fp, "\t\t\t[PollRequest] Received a client request\n");

      for (int i = 0; i < req; i++) {
        ProcessRecvRequest(&pool_wc[i]);
      }
    }
  }
}

// The following  method is responsible for polling RDMA receive
// requests and processing them
inline void SecureWorker::PollDMAControlRequest() {
  struct ibv_wc wc;
  int req = dmacon->recv_check(&wc);

  if (req) {
    text(log_fp,
         "\t\t\t[PollDMAControlRequest] Received a client request %lu \n",
         wc.wr_id);

    if (wc.status != IBV_WC_SUCCESS) {
      info(log_fp, "\t\t\t[PollDMAControlRequest] error %u\n", wc.status);
      return;
    }

    if (wc.wc_flags & IBV_WC_WITH_IMM) {
      text(log_fp, "\t\t\t[ProcessDMAControlRequest] with imm \n");
      ProcessSendRequest(&wc);
    } else {
      ProcessDMAControlRequest(&wc);
    }
  }
}

inline void SecureWorker::ProcessDMAControlRequest(struct ibv_wc* wc) {
  text(log_fp, "\t\t\t[ProcessDMAControlRequest] Create secure ctx\n");
  struct ibv_mr* mr = (struct ibv_mr*)wc->wr_id;  // dma_recv_buf

  text(log_fp, "mr addr %p \n", mr->addr);

  secure_attribure_header_t* h = (secure_attribure_header_t*)mr->addr;
  if (h->type == INIT) {
    text(log_fp, "\t\t\t[ProcessDMAControlRequest] INIT qp\n");
    init_attribure_t* attr =
        (init_attribure_t*)((char*)mr->addr +
                            sizeof(secure_attribure_header_t));
    if (attr->drkey) {
      text(log_fp, "\t\t\t[ProcessDMAControlRequest] Secure ctx with drkey\n");
      this->drkey = true;
      this->master_key = (unsigned char*)malloc(KDFKEYSIZE);
      memcpy(this->master_key, attr->pdkey, KDFKEYSIZE);
      this->kdfctx =
          initkdf(ibv_kdf_type::KDF_CMAC_AES_128, this->master_key, KDFKEYSIZE);
    }

    if (attr->withmemkey) {
      text(log_fp,
           "\t\t\t[ProcessDMAControlRequest] Install memory protection\n");
      this->memkdf = initkdf(ibv_kdf_type::KDF_CMAC_AES_128, NULL, KDFKEYSIZE);
      memcpy(this->pdmemkey, attr->memkey, KDFKEYSIZE);
    }

  } else if (h->type == RTR) {
    rtr_attribure_t* attr =
        (rtr_attribure_t*)((char*)mr->addr + sizeof(secure_attribure_header_t));

    secure_connection_t* seccon = new secure_connection_t();

    //   Connection* con = qpn_to_connection[wc->qp_num];
    uint32_t myqpnum = dmacon->TargetQPN();

    seccon->dest_qp_num = attr->dest_qp_num;
    seccon->recvcon = dmacon;

    text(log_fp, "My qp %u, dest qp %u, remote psn %u  \n", myqpnum,
         attr->dest_qp_num, attr->remote_psn);

    nonce_t receivenonce =
        (attr->remote_psn << 1) + !(myqpnum < attr->dest_qp_num);

    if (this->drkey) {
      seccon->secctx = init(attr->cryptoname, NULL, 0, receivenonce);
      text(log_fp, "\t\t\t[ProcessDMAControlRequest] keylength %u \n",
           seccon->secctx->key_length);
    } else {
      text(log_fp, "\t\t\t[ProcessDMAControlRequest] Secure ctxn\n");
      seccon->secctx = init(attr->cryptoname, attr->key, 0, receivenonce);
    }

    seccon->sendcon = niccon;
    text(log_fp, "\t\t[SecureWorker] new connection QPN %u pushed with %u \n",
         niccon->GetQPN(), niccon->TargetQPN());

    secure_connections[myqpnum] = seccon;           // on receive
    secure_connections[dmacon->GetQPN()] = seccon;  // on receive

  } else if (h->type == RTS) {
    rts_attribure_t* attr =
        (rts_attribure_t*)((char*)mr->addr + sizeof(secure_attribure_header_t));

    //    Connection* con = qpn_to_connection[wc->qp_num];
    uint32_t myqpnum = dmacon->TargetQPN();

    secure_connection_t* seccon = secure_connections[myqpnum];

    seccon->secctx->sendnonce =
        (attr->mypsn << 1) + (myqpnum < seccon->dest_qp_num);

    secure_connections[seccon->dest_qp_num] = seccon;  // on send

    text(log_fp, "sendnonce %lu receivenonce: %lu\n",
         (uint64_t)seccon->secctx->sendnonce,
         (uint64_t)seccon->secctx->recvnonce);
  } else if (h->type == MEMORY_REG) {
    mem_attribure_t* memregion =
        (mem_attribure_t*)((char*)mr->addr + sizeof(secure_attribure_header_t));
    text(log_fp,
         "\t\t\t[ProcessDMAControlRequest] Register memory with rkey %u \n",
         memregion->rkey);
    this->memlookup[memregion->rkey] = (*memregion);
  } else {
    info(log_fp, "\t\t\t[ProcessDMAControlRequest] unknown type %lu \n",
         h->type);
  }

  dmacon->post_recv(wc->wr_id, mr);
}

inline void SecureWorker::ProcessSendRequest(struct ibv_wc* wc) {
  text(log_fp, "ProcessSendRequest \n");

  struct ibv_mr* mr = (struct ibv_mr*)wc->wr_id;  // dma_recv_buf

  if (wc->status == IBV_WC_SUCCESS) {
    uint32_t request_type = (wc->imm_data & IBV_WRID_REQUEST_MASK);

    uint32_t qpn = wc->qp_num;  // qp1
    text(log_fp, "\t\t\t[ProcessSendRequest] for qpn %u \n", qpn);

    secure_connection_t* seccon = secure_connections[qpn];
    if (request_type == IBV_WR_SECURE_READ) {
      text(log_fp, "IBV_WR_SECURE_READ \n");

      int ret = SecureRead(wc->imm_data, seccon, mr);

      if (ret == 0) {
        text(log_fp, "successful read \n");

      } else {
        text(log_fp, "\t\t\t[ProcessSendRequest] read failure\n");
        do {  // TODO delay by sending it to itself
          ret = seccon->recvcon->send_imm(0,
                                          wc->imm_data | IBV_WC_SECURE_FAILURE);
        } while (ret == ENOMEM);
      }

      dmacon->post_recv(wc->wr_id, mr);
      return;
    } else if (request_type == IBV_WR_SECURE_WRITE) {
      text(log_fp, "IBV_WR_SECURE_WRITE %lu %u %u %p %p\n", wc->wr_id,
           wc->imm_data, wc->byte_len, seccon, mr);

      int ret =
          SecureWrite(wc->wr_id | DMA, wc->imm_data, wc->byte_len, seccon, mr);
      if (ret == 0) {
        text(log_fp, "successful write \n");

        return;
      } else {
        text(log_fp, "\t\t\t[ProcessSendRequest] write failure\n");
        do {  // TODO delay by sending it to itself
          ret = seccon->recvcon->send_imm(0,
                                          wc->imm_data | IBV_WC_SECURE_FAILURE);
        } while (ret == ENOMEM);
      }

    } else if (request_type == IBV_WR_SECURE_SEND) {
      text(log_fp, "IBV_WR_SECURE_SEND %lu %u %u %p %p\n", wc->wr_id,
           wc->imm_data, wc->byte_len, seccon, mr);

      int ret =
          SecureSend(wc->wr_id | DMA, wc->imm_data, wc->byte_len, seccon, mr);
      if (ret == 0) {
        text(log_fp, "successful send \n");

        return;
      } else {
        text(log_fp, "\t\t\t[ProcessSendRequest] send failure\n");
        do {  // TODO delay by sending it to itself
          ret = seccon->recvcon->send_imm(0,
                                          wc->imm_data | IBV_WC_SECURE_FAILURE);
        } while (ret == ENOMEM);
      }
    } else {
      info(log_fp, "\t\t\t[ProcessRecvRequest] unknown client request\n");
    }
  }

  info(log_fp, "Not successful ProcessSendRequest \n");

  dmacon->post_recv(wc->wr_id, mr);
  return;
}
/**
 * @description: 
 * @param {ibv_wc*} wc
 * @return {*}
 */
inline void SecureWorker::ProcessRecvRequest(struct ibv_wc* wc) {
  text(log_fp, "ProcessRecvRequest \n");
  //前面处理时将mr指针作为wr_id
  struct ibv_mr* mr = (struct ibv_mr*)wc->wr_id;  // recv_buf

  if (wc->status == IBV_WC_SUCCESS && (wc->wc_flags & IBV_WC_WITH_IMM)) {
    //request_type信息包含在imm_data中
    uint8_t request_type = (wc->imm_data & IBV_WRID_REQUEST_MASK);
    //addr指向的内存前部分包含了transport_header_t 
    //question:报文结构
    transport_header_t* h = (transport_header_t*)(char*)mr->addr;
    // check secure header here 检查flag
    bool withmemkey = (wc->imm_data & IBV_WR_SECURE_MEMORY);
    //witheth是否包含交换信息
    bool witheth = (wc->imm_data & IBV_ETH);

    uint32_t qpn = h->qpn;
    text(log_fp, "\t\t\t[ProcessRecvRequest] for qpn %u %s req type %u\n", qpn,
         witheth ? "with eth" : "no eth", request_type);
  //检索qp连接是否建立保护
    secure_connection_t* seccon = secure_connections[qpn];

    text(log_fp, "\tProtection is %s for qpn %u \n",
         seccon == NULL ? "not installed" : "installed", qpn);
  //question:报文结构
    ext_transport_header_t* eth =
        (ext_transport_header_t*)((char*)mr->addr + sizeof(transport_header_t));

    uint32_t headersize = sizeof(transport_header_t) +
                          (witheth ? sizeof(ext_transport_header_t) : 0);
    //question:macsize是什么东西
    uint32_t payloadoffset = headersize + h->macsize;

    unsigned char* key = NULL;
    if (this->drkey && seccon != nullptr) {
      text(log_fp, "\t\t\t[DRKEY] not cached from qpn %u \n", qpn);

      kdf(this->kdfctx, (unsigned char*)&(qpn), sizeof(qpn), this->derived_key,
          seccon->secctx->key_length);
      key = this->derived_key;
      printBytes(key, seccon->secctx->key_length);
    }

    unsigned char* memkey = NULL;
    if (withmemkey && witheth) {
      text(log_fp, "WE verify memprot \n");
      memcpy(derived_mem_key, this->pdmemkey, KDFKEYSIZE);

      // lookup region
      // region_t origreg = memlookup[wh->rkey];
      auto got = memlookup.find(eth->rkey);
      if (got != memlookup.end()) {
        mem_attribure_t origreg = got->second;
        text(log_fp, "Memory key for %lu %u %u %u \n", origreg.begin,
             (uint32_t)(eth->addr - origreg.begin), eth->length,
             origreg.length);
        calculate_memory_MAC(origreg.begin, eth->addr - origreg.begin,
                             eth->length, origreg.length, derived_mem_key,
                             memkdf);
        memkey = derived_mem_key;
      } else {
        info(log_fp, "Unknown region \n");
      }
    }

    text(log_fp, "\t\t\t[ProcessRecvRequest] header %u payload %u \n",
         headersize, wc->byte_len - payloadoffset);

    bool verified =
        (seccon == nullptr) ||
        onreceive(seccon->secctx, (unsigned char*)mr->addr, headersize,
                  ((unsigned char*)mr->addr) + payloadoffset,
                  wc->byte_len - payloadoffset, tempbuf, key, memkey);

    if (verified) {
      if (request_type == IBV_WR_SECURE_SEND) {
        text(log_fp,
             "\t\t\t[ProcessRecvRequest] Secure read  header %u payload %u %p "
             "\n",
             headersize, wc->byte_len - payloadoffset, seccon);

        int ret;
        do {
          ret = seccon->recvcon->send_imm_signaled(
              (uint64_t)mr, IBV_WR_SECURE_SEND,
              ((char*)mr->addr) + payloadoffset, mr->lkey,
              wc->byte_len - payloadoffset);
        } while (ret == ENOMEM);
        return;
      }

      else if (witheth &&
               request_type ==
                   IBV_WR_SECURE_READ) {  // h->type == IBV_WR_SECURE_READ
        text(log_fp, " Read from %lu %u to %lu %u %u\n", eth->addr, eth->rkey,
             (uint64_t)mr->addr, mr->lkey, eth->length);

        SecureReadWriteCtx* ctx = MemPoolSecCtx.malloc();

        pending_dma_req++;
        uint64_t wr_id = ((uint64_t)ctx) | VIRT_ADDR;
        int ret;
        do {  // TODO delay by sending it to itself
          ret = seccon->recvcon->read_signaled(wr_id, eth->addr, eth->rkey,
                                               (char*)mr->addr, mr->lkey,
                                               eth->length);
          if (ret) {
            text(log_fp, " Read from %lu %u to %lu %u %u\n", eth->addr,
                 eth->rkey, (uint64_t)mr->addr, mr->lkey, eth->length);
          }
        } while (ret == ENOMEM);
        SecureReadWriteCtx::Set(ctx, seccon, wc->imm_data, mr);

        return;
      } else if (witheth && request_type == IBV_WR_SECURE_WRITE) {
        text(log_fp, " Write from %lu %u to %lu %u \n",
             (uint64_t)mr->addr + payloadoffset, mr->lkey, eth->addr,
             eth->rkey);
        SecureReadWriteCtx* ctx = MemPoolSecCtx.malloc();
        uint64_t wr_id = ((uint64_t)ctx) | VIRT_ADDR;
        int ret;
        do {  // TODO delay by sending it to itself
          ret = seccon->recvcon->write_signaled(
              wr_id, (char*)mr->addr + payloadoffset, mr->lkey, eth->addr,
              eth->rkey, eth->length);
        } while (ret == ENOMEM);
        SecureReadWriteCtx::Set(ctx, seccon, wc->imm_data, mr);

        return;
      } else if (request_type == IBV_WR_SECURE_READ) {
        auto elem = read_queue.front();
        read_queue.pop();

        text(log_fp, " DMA read finish %lu %u   \n",
             (uint64_t)mr->addr + payloadoffset, mr->lkey);

        if (elem.imm_data & IBV_WR_SECURE_SIGNALED) {
          seccon->recvcon->write_with_imm_signaled(
              wc->wr_id, elem.imm_data, (char*)mr->addr + payloadoffset,
              mr->lkey, elem.addr, elem.rkey, wc->byte_len - payloadoffset);
        } else {
          seccon->recvcon->write_signaled(
              wc->wr_id, (char*)mr->addr + payloadoffset, mr->lkey, elem.addr,
              elem.rkey, wc->byte_len - payloadoffset);
        }

        return;
      } else if (request_type == IBV_WR_SECURE_WRITE) {
        text(log_fp, " DMA write finish \n");
        auto elem = write_queue.front();
        write_queue.pop();
        dmacon->write_with_imm_signaled(0, elem.imm_data, 0, 0, 0, 0, 0);

        used_buffers--;
        niccon->post_recv(wc->wr_id, mr);
        return;

      } else {
        info(log_fp, "\t\t\t[ProcessRecvRequest] unknown client request\n");
      }
    }
    text(log_fp, "\t\t\t[ProcessRecvRequest] not verified\n");
  }

  info(log_fp, "Not successful ProcessRecvRequest \n");
  used_buffers--;
  niccon->post_recv(wc->wr_id, mr);
  return;
}

void SecureWorker::PollDMASendCompletion() {
  // struct ibv_wc pool_wc[20];
  struct ibv_wc pool_wc;
  int req = dmacon->send_check(&pool_wc);
  if (req) {
    text(log_fp, "\t\t\t[PollDMASendCompletion] %d\n", req);
  }
  if (req == 1 && pool_wc.wr_id) {
    text(log_fp, "\t\t\t[PollDMASendCompletion] Received DMA Completion\n");
    ProcessDMACompletion(&pool_wc);
  }
}

void SecureWorker::PollClientSendCompletion() {
  struct ibv_wc pool_wc;
  int req = niccon->send_check(&pool_wc);
  if (req) {
    pending_req--;
    text(log_fp, "\t\t\t[PollClientSendCompletion] %d\n", req);
  }
  if (req == 1 && pool_wc.wr_id) {
    text(
        log_fp,
        "\t\t\t[PollClientSendCompletion] Received a client send Completion\n");
    ProcessClientCompletion(&pool_wc);
  }
}

inline void SecureWorker::ProcessDMACompletion(struct ibv_wc* wc) {
  if (wc->status != IBV_WC_SUCCESS) {
    text(log_fp, "\t\t\t[ProcessDMACompletion] wc->status %u\n", wc->status);
    text(log_fp, "\t\t\t[ProcessDMACompletion] failure\n");

    if (wc->wr_id & VIRT_ADDR) {
      wc->wr_id = wc->wr_id & ~VIRT_ADDR;
      SecureReadWriteCtx* ctx = (SecureReadWriteCtx*)wc->wr_id;
      niccon->post_recv((uint64_t)(ctx->mr), ctx->mr);
      MemPoolSecCtx.free(ctx);
    } else {
      struct ibv_mr* mr = (struct ibv_mr*)wc->wr_id;
      niccon->post_recv(wc->wr_id, mr);
    }

    return;
  }


  if (!(wc->wr_id & VIRT_ADDR)) {
    struct ibv_mr* mr = (struct ibv_mr*)wc->wr_id;
    used_buffers--;
    niccon->post_recv(wc->wr_id, mr);
    return;
  }

  wc->wr_id = wc->wr_id & ADDR_MASK;

  SecureReadWriteCtx* ctx = (SecureReadWriteCtx*)wc->wr_id;
  //   struct ibv_mr *mr =  ctx->mr;

  uint32_t immdata = ctx->imm_data;
  secure_connection_t* seccon = ctx->seccon;

  // TODO. Should I add encryption here?
  if (immdata & IBV_WR_SECURE_READ) {
    text(log_fp, "\t\t\t[ProcessDMACompletion] read signaled\n");

    pending_dma_req--;
    pending_req++;

    SecureReadReply(wc->wr_id | VIRT_ADDR, immdata, wc->byte_len, seccon,
                    ctx->mr);

    return;
  } else {  // for write

    if (immdata & IBV_WR_SECURE_SIGNALED) {
      text(log_fp, "\t\t\t[ProcessDMACompletion] write signaled\n");
      // int ret;
      pending_req++;

      SecureWriteReply(immdata, seccon);
      text(log_fp, "\t\t\t[SecureWriteReply] after send\n");
    }
    text(log_fp, "\t\t\t[ProcessDMACompletion] post_recv\n");
    used_buffers--;
    niccon->post_recv((uint64_t)ctx->mr, ctx->mr);
    MemPoolSecCtx.free(ctx);
  }
  return;
}

inline void SecureWorker::ProcessClientCompletion(struct ibv_wc* wc) {
  text(log_fp, "[ProcessClientCompletion]  %u \n", wc->status);
  //    assert(wc->status == IBV_WC_SUCCESS);
  if (wc->wr_id & VIRT_ADDR) {
    wc->wr_id = wc->wr_id & ~VIRT_ADDR;
    SecureReadWriteCtx* ctx = (SecureReadWriteCtx*)wc->wr_id;

    used_buffers--;
    niccon->post_recv((uint64_t)ctx->mr, ctx->mr);
    MemPoolSecCtx.free(ctx);

  } else if (wc->wr_id & DMA) {
    wc->wr_id = wc->wr_id & ~DMA;
    struct ibv_mr* mr = (struct ibv_mr*)wc->wr_id;
    dmacon->post_recv(wc->wr_id, mr);  // TODO
  } else {
    struct ibv_mr* mr = (struct ibv_mr*)wc->wr_id;
    niccon->post_recv(wc->wr_id, mr);  // TODO
  }
}

inline int SecureWorker::SecureWrite(uint64_t wr_id, uint32_t imm_data,
                                     uint32_t originallength,
                                     secure_connection_t* seccon,
                                     struct ibv_mr* mr) {
  uint32_t tagsize = seccon->secctx->tagbytes;
  uint32_t header_length =
      sizeof(transport_header_t) + sizeof(ext_transport_header_t) + tagsize;
  uint32_t oldheadersize = sizeof(write_header_t);
  uint32_t length = originallength - oldheadersize;

  text(log_fp, "\t\t\t[Write] additional header is %u \n", header_length);

  // unsigned char* header = (unsigned
  // char*)this->circular_buf.get(header_length);

  write_header_t originalwh = *(write_header_t*)((char*)mr->addr);  //

  // Check whether we need to derive key
  unsigned char* key = NULL;
  if (this->drkey) {
    text(log_fp, "\t\t\t[DRKEY] from qpn %u \n", seccon->dest_qp_num);
    kdf(kdfctx, (unsigned char*)&seccon->dest_qp_num,
        sizeof(seccon->dest_qp_num), this->derived_key, KDFKEYSIZE);
    key = this->derived_key;
    printBytes(key, seccon->secctx->key_length);
  }

  unsigned char* memkey = NULL;
  if (imm_data & IBV_WR_SECURE_MEMORY) {
    text(log_fp, "\t\t\t[Write] calculate_memory_MAC  \n");
    length -= sizeof(region_t);
    oldheadersize += sizeof(region_t);
    region_t* remregion = (region_t*)((char*)mr->addr + sizeof(write_header_t));
    memcpy(this->derived_mem_key, remregion->memkey, KDFKEYSIZE);

    printBytes(this->derived_mem_key, KDFKEYSIZE);
    calculate_memory_MAC(remregion->begin, originalwh.remote - remregion->begin,
                         length, remregion->length, this->derived_mem_key,
                         memkdf);
    printBytes(this->derived_mem_key, KDFKEYSIZE);

    memkey = this->derived_mem_key;
  }

  unsigned char* header =
      (unsigned char*)mr->addr + oldheadersize - header_length;

  transport_header_t* th = (transport_header_t*)header;

  // Fill transport header
  th->macsize = tagsize;
  th->qpn = seccon->dest_qp_num;

  ext_transport_header_t* eth =
      (ext_transport_header_t*)(header + sizeof(transport_header_t));
  eth->addr = originalwh.remote;
  eth->rkey = originalwh.rkey;
  eth->length = length;

  char* local = (((char*)mr->addr) + oldheadersize);

  onsend(seccon->secctx, header, header_length - tagsize, (unsigned char*)local,
         length, key, memkey);

  /*   // set a header
     sge[0].addr = (uint64_t) (uintptr_t)header;
     sge[0].length = header_length;
     sge[0].lkey = this->circular_buf.lkey() ;

     sge[1].addr = (uint64_t) (uintptr_t)local;
     sge[1].length = length ;
     sge[1].lkey = mr->lkey ;
 */
  struct ibv_sge sge;
  sge.addr = (uint64_t)(uintptr_t)header;
  sge.length = header_length + length;
  sge.lkey = mr->lkey;

  // text(log_fp,"[Write] %lu %u %u %lu %u %u\n",sge[0].addr, sge[0].length,
  // sge[0].lkey, sge[1].addr, sge[1].length, sge[1].lkey );

  text(log_fp, "[Write] %lu %u %u\n", sge.addr, sge.length, sge.lkey);

  struct ibv_send_wr wr, *bad;

  wr.wr_id = wr_id;
  wr.next = NULL;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  wr.opcode = IBV_WR_SEND_WITH_IMM;
  wr.imm_data = imm_data | IBV_ETH;
  wr.send_flags = IBV_SEND_SIGNALED;

  assert(seccon->sendcon != NULL);
  int ret = ibv_post_send(seccon->sendcon->id->qp, &wr, &bad);

  if (ret == 0 && (imm_data & IBV_WR_SECURE_SIGNALED)) {
    write_queue.push({seccon->recvcon, imm_data});
  }

  return ret;
}

inline int SecureWorker::SecureSend(uint64_t wr_id, uint32_t imm_data,
                                    uint32_t length,
                                    secure_connection_t* seccon,
                                    struct ibv_mr* mr) {
  uint32_t tagsize = seccon->secctx->tagbytes;
  uint32_t header_length = sizeof(transport_header_t) + tagsize;

  text(log_fp, "\t\t\t[Write] additional header is %u \n", header_length);

  // Check whether we need to derive key
  unsigned char* key = NULL;
  if (this->drkey) {
    text(log_fp, "\t\t\t[DRKEY] from qpn %u \n", seccon->dest_qp_num);
    kdf(kdfctx, (unsigned char*)&seccon->dest_qp_num,
        sizeof(seccon->dest_qp_num), this->derived_key, KDFKEYSIZE);
    key = this->derived_key;
    printBytes(key, seccon->secctx->key_length);
  }

  unsigned char* header = (unsigned char*)mr->addr - header_length;

  transport_header_t* th = (transport_header_t*)header;

  // Fill transport header
  th->macsize = tagsize;
  // th->type = IBV_WR_SECURE_WRITE;
  th->qpn = seccon->dest_qp_num;

  char* local = ((char*)mr->addr);

  onsend(seccon->secctx, header, header_length - tagsize, (unsigned char*)local,
         length, key, NULL);

  struct ibv_sge sge;
  sge.addr = (uint64_t)(uintptr_t)header;
  sge.length = header_length + length;
  sge.lkey = mr->lkey;

  text(log_fp, "[Send] %lu %u %u\n", sge.addr, sge.length, sge.lkey);

  struct ibv_send_wr wr, *bad;

  wr.wr_id = wr_id;
  wr.next = NULL;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  wr.opcode = IBV_WR_SEND_WITH_IMM;
  wr.imm_data = IBV_WR_SECURE_SEND;
  wr.send_flags = IBV_SEND_SIGNALED;

  assert(seccon->sendcon != NULL);
  int ret = ibv_post_send(seccon->sendcon->id->qp, &wr, &bad);

  return ret;
}

inline int SecureWorker::SecureRead(uint32_t imm_data,
                                    secure_connection_t* seccon,
                                    struct ibv_mr* mr) {
  struct ibv_sge sge;

  uint32_t tagsize = seccon->secctx->tagbytes;
  uint32_t header_length =
      sizeof(transport_header_t) + sizeof(ext_transport_header_t) + tagsize;

  text(log_fp, "\t\t\t[Read] additional header is %u \n", header_length);

  unsigned char* header = (unsigned char*)this->circular_buf.get(header_length);
  transport_header_t* th = (transport_header_t*)header;

  // Fill transport header
  th->macsize = tagsize;
  // th->type = IBV_WR_SECURE_WRITE;
  th->qpn = seccon->dest_qp_num;

  // Fill write header

  read_header_t* originalrh = (read_header_t*)((char*)mr->addr);  //

  uint32_t length = originalrh->length;

  // Check whether we need to derive key
  unsigned char* key = NULL;
  if (this->drkey) {
    text(log_fp, "\t\t\t[DRKEY] from qpn %u \n", seccon->dest_qp_num);
    kdf(kdfctx, (unsigned char*)&th->qpn, sizeof(th->qpn), this->derived_key,
        KDFKEYSIZE);
    key = this->derived_key;
    printBytes(key, seccon->secctx->key_length);
  }

  unsigned char* memkey = NULL;
  if (imm_data & IBV_WR_SECURE_MEMORY) {
    text(log_fp, "\t\t\t[Read] calculate_memory_MAC  \n");
    //  memcpy(this->derived_mem_key, memkey, KDFKEYSIZE);

    region_t* remregion = (region_t*)((char*)mr->addr + sizeof(read_header_t));
    text(log_fp, "\t Begin: %lu offset %lu, length %u reglength %u kdf %p\n",
         remregion->begin, (originalrh->from - remregion->begin), length,
         remregion->length, memkdf);

    printBytes(remregion->memkey, KDFKEYSIZE);
    calculate_memory_MAC(remregion->begin, originalrh->from - remregion->begin,
                         length, remregion->length, remregion->memkey, memkdf);
    printBytes(remregion->memkey, KDFKEYSIZE);
    memkey = remregion->memkey;
  }

  ext_transport_header_t* eth =
      (ext_transport_header_t*)(header + sizeof(transport_header_t));
  eth->addr = originalrh->from;
  eth->rkey = originalrh->from_rkey;
  eth->length = length;

  onsend(seccon->secctx, header, header_length - tagsize, NULL, 0, key, memkey);

  // set a header
  sge.addr = (uint64_t)(uintptr_t)header;
  sge.length = header_length;
  sge.lkey = this->circular_buf.lkey();

  struct ibv_send_wr wr, *bad;

  wr.wr_id = 0;
  wr.next = NULL;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  wr.opcode = IBV_WR_SEND_WITH_IMM;
  wr.imm_data = imm_data | IBV_ETH;
  wr.send_flags = IBV_SEND_SIGNALED;

  assert(seccon->sendcon != NULL);
  int ret = ibv_post_send(seccon->sendcon->id->qp, &wr, &bad);

  if (ret == 0) {
    read_queue.push(
        {seccon->recvcon, originalrh->to, imm_data, originalrh->to_rkey});
  }

  return ret;
}

inline int SecureWorker::SecureWriteReply(uint32_t imm_data,
                                          secure_connection_t* seccon) {
  struct ibv_sge sge;

  uint32_t tagsize = seccon->secctx->tagbytes;
  uint32_t header_length = sizeof(transport_header_t) + tagsize;

  imm_data = IBV_WR_SECURE_WRITE;
  //   imm_data = imm_data & ~IBV_ETH;
  //    imm_data = imm_data & ~IBV_WR_SECURE_MEMORY;

  text(log_fp, "\t\t\t[SecureWriteReply] additional header is %u \n",
       header_length);

  unsigned char* header = (unsigned char*)this->circular_buf.get(header_length);
  transport_header_t* th = (transport_header_t*)header;

  // Fill transport header
  th->macsize = tagsize;
  th->qpn = seccon->dest_qp_num;

  // Check whether we need to derive key
  unsigned char* key = NULL;
  if (this->drkey) {
    text(log_fp, "\t\t\t[DRKEY] from qpn %u \n", seccon->dest_qp_num);
    kdf(kdfctx, (unsigned char*)&th->qpn, sizeof(th->qpn), this->derived_key,
        KDFKEYSIZE);
    key = this->derived_key;
    printBytes(key, seccon->secctx->key_length);
  }

  onsend(seccon->secctx, header, header_length - tagsize, 0, 0, key, NULL);

  // set a header
  sge.addr = (uint64_t)(uintptr_t)header;
  sge.length = header_length;
  sge.lkey = this->circular_buf.lkey();

  struct ibv_send_wr wr, *bad;

  wr.wr_id = 0;
  wr.next = NULL;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  wr.opcode = IBV_WR_SEND_WITH_IMM;
  wr.imm_data = imm_data;
  wr.send_flags = IBV_SEND_SIGNALED;
  text(log_fp, "\t\t\t[SecureWriteReply] before send %p %p  \n",
       seccon->sendcon, seccon->sendcon);
  return ibv_post_send(seccon->sendcon->id->qp, &wr, &bad);
}

inline int SecureWorker::SecureReadReply(uint64_t wr_id, uint32_t imm_data,
                                         uint32_t length,
                                         secure_connection_t* seccon,
                                         struct ibv_mr* mr) {
  uint32_t tagsize = seccon->secctx->tagbytes;
  uint32_t header_length = sizeof(transport_header_t) + tagsize;

  imm_data = IBV_WR_SECURE_READ;

  text(log_fp, "\t\t\t[SecureReadReply] additional header is %u \n",
       header_length);

  unsigned char* header = (unsigned char*)mr->addr - header_length;
  transport_header_t* th = (transport_header_t*)header;

  // Fill transport header
  th->macsize = tagsize;
  th->qpn = seccon->dest_qp_num;

  // Check whether we need to derive key
  unsigned char* key = NULL;
  if (this->drkey) {
    text(log_fp, "\t\t\t[DRKEY] from qpn %u \n", seccon->dest_qp_num);
    kdf(kdfctx, (unsigned char*)&th->qpn, sizeof(th->qpn), this->derived_key,
        KDFKEYSIZE);
    key = this->derived_key;
    printBytes(key, seccon->secctx->key_length);
  }

  onsend(seccon->secctx, header, header_length - tagsize,
         (unsigned char*)mr->addr, length, key, NULL);

  struct ibv_sge sge;
  // set a header
  sge.addr = (uint64_t)(uintptr_t)header;
  sge.length = header_length + length;
  sge.lkey = mr->lkey;

  struct ibv_send_wr wr, *bad;

  wr.wr_id = wr_id;
  wr.next = NULL;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  wr.opcode = IBV_WR_SEND_WITH_IMM;
  wr.imm_data = imm_data;
  wr.send_flags = IBV_SEND_SIGNALED;

  return ibv_post_send(seccon->sendcon->id->qp, &wr, &bad);
}
