#pragma once
#include <fcntl.h>
#include <infiniband/verbs.h>
#include <inttypes.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <atomic>
#include <vector>
#include "../utilities/debug.h"

struct Connection {
  struct rdma_cm_id *id;
  const uint32_t max_inline_data;
  const uint32_t max_recv_size;
  const uint32_t max_send_size;
  const bool with_shared_receive;
  uint32_t target_qp_num;

  Connection(struct rdma_cm_id *id, uint32_t max_inline_data,
             uint32_t max_recv_size, uint32_t max_send_size,
             bool with_shared_receive = false)
      : id(id),
        max_inline_data(max_inline_data),
        max_recv_size(max_recv_size),
        max_send_size(max_send_size),
        with_shared_receive(with_shared_receive) {}

  ~Connection() {
    if (id) {
      if (with_shared_receive) {
        id->recv_cq_channel = NULL;
      }
      rdma_disconnect(this->id);
      rdma_destroy_ep(this->id);
      this->id = NULL;
    }
  }

  uint32_t GetQPN() const { return this->id->qp->qp_num; }

  uint32_t TargetQPN() const { return this->target_qp_num; }

  void SetTargetQPN() {
    struct ibv_qp_attr attr;
    struct ibv_qp_init_attr init_attr;
    int ret = ibv_query_qp(id->qp, &attr, IBV_QP_DEST_QPN, &init_attr);
    assert(ret >= 0);
    this->target_qp_num = attr.dest_qp_num;
  }

  inline uint32_t send_size() { return this->max_send_size; }

  bool check_status() {
    int ret;
    struct rdma_cm_event *event;

    ret = rdma_get_cm_event(id->channel, &event);
    if (ret) {
      perror("rdma_get_cm_event");
      exit(ret);
    }
    switch (event->event) {
      case RDMA_CM_EVENT_ADDR_ERROR:
      case RDMA_CM_EVENT_ROUTE_ERROR:
      case RDMA_CM_EVENT_CONNECT_ERROR:
      case RDMA_CM_EVENT_UNREACHABLE:
      case RDMA_CM_EVENT_REJECTED:

        text(log_fp, "[rdma_get_cm_event] Error %u \n", event->event);
        break;

      case RDMA_CM_EVENT_DISCONNECTED:
        text(log_fp, "[rdma_get_cm_event] Disconnect %u \n", event->event);
        break;

      case RDMA_CM_EVENT_DEVICE_REMOVAL:
        text(log_fp, "[rdma_get_cm_event] Removal %u \n", event->event);
        break;
      default:
        text(log_fp, "[rdma_get_cm_event] Unknown %u \n", event->event);
    }
    rdma_ack_cm_event(event);
    return false;
  }

  int get_event_fd() {
    assert(this->id->channel != NULL && "Channel is empty");
    int options = fcntl(this->id->channel->fd, F_GETFL, 0);
  //为fd添加非阻塞文件状态
    if (fcntl(this->id->channel->fd, F_SETFL, options | O_NONBLOCK)) {
      perror("[RDMA_COM] cannot set server_client to non-blocking mode");
      exit(1);
      return 0;
    }

    return this->id->channel->fd;
  }


  struct ibv_mr *reg_mem(uint32_t size) {
    char *buf = (char *)aligned_alloc(4096, size);
    struct ibv_mr *mr =
    //在pd中注册mr，并设置远端读写权限
        ibv_reg_mr(id->qp->pd, buf, size, IBV_ACCESS_REMOTE_WRITE |
                                              IBV_ACCESS_LOCAL_WRITE |
                                              IBV_ACCESS_REMOTE_READ);
    ;
    if (!mr) {
      perror("rdma_reg_msgs for recv_buf");
      free(buf);
      exit(1);
    }
    return mr;
  }

//根据参数重写函数，直接传入内存地址，将其注册为mr
  struct ibv_mr *reg_mem(void *buf, uint32_t size) {
    return ibv_reg_mr(id->qp->pd, buf, size, IBV_ACCESS_REMOTE_WRITE |
                                                 IBV_ACCESS_LOCAL_WRITE |
                                                 IBV_ACCESS_REMOTE_READ);
    ;
  }

  void dereg_mem(struct ibv_mr *mr, bool free_mem = false) {
    void *buf = mr->addr;
    ibv_dereg_mr(mr);
    //注销mr不会释放对应的内存
    if (free_mem) {
      free(buf);
    }
  }

  inline int write(char *from, uint32_t lkey, uint64_t to, uint32_t rkey,
                   uint32_t length) {
    struct ibv_sge sge;

    sge.addr = (uint64_t)(uintptr_t)from;
    sge.length = length;
    sge.lkey = lkey;
    struct ibv_send_wr wr, *bad;
  
    wr.wr_id = 0;
    //TODO:目前见过的都是一个wr，wr中只有一个sge
    wr.next = NULL;//wr也是一个链表
    wr.sg_list = &sge; //每个wr只有1个sge，如果需要多次传输，是一次传输下发一次，还是综合下发一次，那么num_sge怎么计算
    wr.num_sge = 1;
    wr.opcode = IBV_WR_RDMA_WRITE;
    wr.send_flags = 0;
  //inline将数据放在wqe的payload中，网卡获取后直接发送，不需要通过lkey去读取数据
    if (length <= max_inline_data && max_inline_data) {
      wr.send_flags |= IBV_SEND_INLINE;
    }

    wr.wr.rdma.remote_addr = to;
    wr.wr.rdma.rkey = rkey;
    return ibv_post_send(id->qp, &wr, &bad);
  }

  inline int write_signaled(uint64_t wr_id, char *from, uint32_t lkey,
                            uint64_t to, uint32_t rkey, uint32_t length) {
    struct ibv_sge sge;

    sge.addr = (uint64_t)(uintptr_t)from;
    sge.length = length;
    sge.lkey = lkey;
    struct ibv_send_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_RDMA_WRITE;
/*sg_list中指定的本地内存缓冲区的内容正在发送和写入远程 QP 虚拟空间中的连续内存范围块。
这并不一定意味着远程内存在物理上是连续的。远程 QP 中不会消耗任何接收请求。*/
    wr.send_flags = IBV_SEND_SIGNALED;

    if (length <= max_inline_data && max_inline_data) {
      wr.send_flags |= IBV_SEND_INLINE;
    }

    wr.wr.rdma.remote_addr = to;
    wr.wr.rdma.rkey = rkey;

    return ibv_post_send(id->qp, &wr, &bad);
  }

  inline int write_with_imm_signaled(uint64_t wr_id, uint32_t imm_data,
                                     char *from, uint32_t lkey, uint64_t to,
                                     uint32_t rkey, uint32_t length) {
    struct ibv_sge sge;

    sge.addr = (uint64_t)(uintptr_t)from;//本地数据存储地址
    sge.length = length;//数据长度
    sge.lkey = lkey;//local key

    struct ibv_send_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
    /*
IBV_WR_RDMA_WRITE_WITH_IMM - 与IBV_WR_RDMA_WRITE相同，
但接收请求将从远程 QP 的接收队列的头部使用，即时数据将在消息中发送。此值将在为远程 QP 中消耗的接收请求生成的WC中可用
*/
    wr.imm_data = imm_data;

    wr.send_flags = IBV_SEND_SIGNALED;

    if (length <= max_inline_data && max_inline_data) {
      wr.send_flags |= IBV_SEND_INLINE;
    }

    wr.wr.rdma.remote_addr = to;
    wr.wr.rdma.rkey = rkey;

    return ibv_post_send(id->qp, &wr, &bad);
  }

  inline int read(uint64_t from, uint32_t rkey, char *to, uint32_t lkey,
                  uint32_t length) {
    struct ibv_sge sge;

    sge.addr = (uint64_t)(uintptr_t)to;  //本数据存储地址
    sge.length = length; //应该读取数据长度
    sge.lkey = lkey; //local key
    struct ibv_send_wr wr, *bad;

    wr.wr_id = 0;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_RDMA_READ;
    /*正在从远程 QP 虚拟空间中的连续内存范围块读取数据，
    并将其写入 sg_list 中指定的本地内存缓冲区。远程 QP 中不会消耗任何接收请求。*/
    wr.send_flags = 0;

    wr.wr.rdma.remote_addr = (uint64_t)(uintptr_t)from;
    wr.wr.rdma.rkey = rkey;

    return ibv_post_send(id->qp, &wr, &bad);
  }

  inline int read_signaled(uint64_t wr_id, uint64_t from, uint32_t rkey,
                           char *to, uint32_t lkey, uint32_t length) {
    struct ibv_sge sge;

    sge.addr = (uint64_t)(uintptr_t)to;
    sge.length = length;
    sge.lkey = lkey;
    struct ibv_send_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_RDMA_READ;
    wr.send_flags = IBV_SEND_SIGNALED;

    wr.wr.rdma.remote_addr = (uint64_t)(uintptr_t)from;
    wr.wr.rdma.rkey = rkey;

    return ibv_post_send(id->qp, &wr, &bad);
  }

  inline void post_recv(uint64_t buf_addr, uint32_t length, uint32_t lkey,
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

    int ret = ibv_post_recv(id->qp, &wr, &bad);
    if (ret) {
      perror("\t[post_recv] ibv_post_recv");
      return;
    }
  }

  inline void post_recv(uint64_t wr_id, struct ibv_mr *mr) {
    post_recv((uint64_t)mr->addr, mr->length, mr->lkey, wr_id);
  }

  inline void post_shared_recv(uint64_t buf_addr, uint32_t length,
                               uint32_t lkey, uint64_t wr_id) {
    struct ibv_sge sge;

    sge.addr = buf_addr;
    sge.length = length;
    sge.lkey = lkey;

    struct ibv_recv_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    int ret = ibv_post_srq_recv(id->qp->srq, &wr, &bad);
    if (ret) {
      perror("\t[post_recv] ibv_post_srq_recv");
      return;
    }
  }

  inline void post_shared_recv(uint64_t wr_id, struct ibv_mr *mr) {
    post_shared_recv((uint64_t)mr->addr, mr->length, mr->lkey, wr_id);
  }

  inline int send_signaled(uint64_t wr_id, char *buf_addr = NULL,
                           uint32_t lkey = 0, uint32_t length = 0) {
    struct ibv_sge sge;
    sge.addr = (uint64_t)(uintptr_t)buf_addr;
    sge.length = length;
    sge.lkey = lkey;
    struct ibv_send_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND;

    wr.send_flags = IBV_SEND_SIGNALED;

    if (length <= max_inline_data && max_inline_data) {
      wr.send_flags |= IBV_SEND_INLINE;
    }

    return ibv_post_send(id->qp, &wr, &bad);
    ;
  }

  inline int send_imm_signaled(uint64_t wr_id, uint32_t imm_data,
                               char *buf_addr = NULL, uint32_t lkey = 0,
                               uint32_t length = 0) {
    struct ibv_sge sge;
    sge.addr = (uint64_t)(uintptr_t)buf_addr;
    sge.length = length;
    sge.lkey = lkey;
    struct ibv_send_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND_WITH_IMM;
/*为此 WR 设置完成通知指示符。  
这意味着如果 QP 是用 sq_sig_all=0 创建的，那么当这个 WR 的处理结束时，将生成一个 Work Completion。  
如果 QP 是使用 sq_sig_all=1 创建的，则此标志不会有任何影响*/
    wr.send_flags = IBV_SEND_SIGNALED; //减少WC的产生和对WC的读取次数

    if (length <= max_inline_data && max_inline_data) {
      wr.send_flags |= IBV_SEND_INLINE;
    }

    wr.imm_data = imm_data;

    return ibv_post_send(id->qp, &wr, &bad);
    ;
  }

  inline int send_imm(uint64_t wr_id, uint32_t imm_data, char *buf_addr = NULL,
                      uint32_t lkey = 0, uint32_t length = 0) {
    struct ibv_sge sge;
    sge.addr = (uint64_t)(uintptr_t)buf_addr;
    sge.length = length;
    sge.lkey = lkey;
    struct ibv_send_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND_WITH_IMM;

    wr.imm_data = imm_data;

    if (length <= max_inline_data && max_inline_data) {
      wr.send_flags |= IBV_SEND_INLINE;
    }

    return ibv_post_send(id->qp, &wr, &bad);
    ;
  }

  inline int blocking_recv(struct ibv_wc *wc) {
    int ret;
    while ((ret = rdma_get_recv_comp(id, wc)) == 0)
      ;
    if (ret < 0) {
      perror("\t[blocking_recv] rdma_get_recv_comp");
    }

    return ret;
  }

  inline int recv_check(struct ibv_wc *wc, int num = 1) {
    int ret = ibv_poll_cq(id->qp->recv_cq, num, wc);
    ;

    if (ret < 0) {
      perror("rdma_get_recv_comp");
    }

    return ret;
  }

  inline int send_check(struct ibv_wc *wc, int num = 1) {
    int ret = ibv_poll_cq(id->qp->send_cq, num, wc);

    if (ret < 0) {
      perror("rdma_get_recv_comp");
    }

    return ret;
  }
};

class SharedSend {
  struct ibv_comp_channel *channel;
  struct ibv_cq *send_cq;
  uint32_t _send_size;

 public:
  SharedSend(struct ibv_comp_channel *channel, struct ibv_cq *send_cq,
             uint32_t _send_size)
      : channel(channel), send_cq(send_cq), _send_size(_send_size) {
    // empty
  }

  ~SharedSend(){};

  int blocking_send_check(struct ibv_wc *wc) {
    int ret = -1;
    struct ibv_cq *ev_cq;
    void *ev_ctx;
    do {
      ret = ibv_poll_cq(this->send_cq, 1, wc);
      if (ret) break;

      ret = ibv_req_notify_cq(this->send_cq, 0);
      if (ret) exit(1);

      ret = ibv_poll_cq(this->send_cq, 1, wc);
      if (ret) break;

      ret = ibv_get_cq_event(this->channel, &ev_cq, &ev_ctx);
      assert(ev_cq == this->send_cq);
      if (ret) return ret;

      ibv_ack_cq_events(this->send_cq, 1);
    } while (1);

    return ret;
  }

  inline int send_check(struct ibv_wc *wc, uint32_t num = 1) {
    return ibv_poll_cq(this->send_cq, num, wc);
  }

  inline uint32_t send_size() { return this->_send_size; }
};

class SharedReceive {
  struct ibv_pd *pd;
  struct ibv_srq *srq;
  struct ibv_qp *qp;
  struct ibv_comp_channel *channel;
  struct ibv_cq *recv_cq;
  uint32_t _receive_size;

 public:
  SharedReceive(struct ibv_pd *pd, struct ibv_srq *srq,
                struct ibv_comp_channel *channel, struct ibv_cq *rcq,
                uint32_t receive_size)
      : pd(pd),
        srq(srq),
        channel(channel),
        recv_cq(rcq),
        _receive_size(receive_size) {
    // empty
  }

  ~SharedReceive(){};

  void install_qp(struct ibv_qp *qp) { this->qp = qp; }

  inline struct ibv_mr *reg_mem(uint32_t size) {
    char *buf = (char *)aligned_alloc(4096, size);
    return reg_mem(buf, size);
  }

  inline struct ibv_mr *reg_mem(void *buf, uint32_t size) {
    struct ibv_mr *ret = ibv_reg_mr(
        this->pd, buf, size, IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_LOCAL_WRITE |
                                 IBV_ACCESS_REMOTE_READ);
    if (!ret) {
      perror("rdma_reg_msgs for recv_buf");
      exit(1);
    }
    return ret;
  }

  inline void post_recv(uint64_t buf_addr, uint32_t length, uint32_t lkey,
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

    int ret = ibv_post_recv(this->qp, &wr, &bad);
    if (ret) {
      perror("\t[post_recv] ibv_post_recv");
      return;
    }
  }

  inline void post_recv(uint64_t wr_id, struct ibv_mr *mr) {
    post_recv((uint64_t)mr->addr, mr->length, mr->lkey, wr_id);
  }

  inline int post_shared_recv(uint64_t wr_id, struct ibv_mr *mr) {
    return post_shared_recv(wr_id, (uint64_t)mr->addr, mr->length, mr->lkey);
  }

  inline int post_shared_recv(uint64_t wr_id, uint64_t buf_addr,
                              uint32_t length, uint32_t lkey) {
    struct ibv_sge sge;

    sge.addr = buf_addr;
    sge.length = length;
    sge.lkey = lkey;

    struct ibv_recv_wr wr, *bad;

    wr.wr_id = wr_id;
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;

    return ibv_post_srq_recv(this->srq, &wr, &bad);
  }

  inline int recv_check(struct ibv_wc *wc, uint32_t num = 1) {
    return ibv_poll_cq(this->recv_cq, num, wc);
    ;
  }

  inline uint32_t receive_size() { return this->_receive_size; }
};

struct shared_connection_info {
  struct ibv_srq *srq;

  struct ibv_comp_channel *receive_channel;
  struct ibv_cq *rcq;

  struct ibv_comp_channel *send_channel;
  struct ibv_cq *scq;
};

class RDMA_COM {
  // struct ibv_device *dev;

  struct ibv_srq *srq = NULL;  // shared queue

  struct ibv_comp_channel *receive_channel = NULL;
  struct ibv_cq *rcq = NULL;

  struct ibv_comp_channel *send_channel = NULL;
  struct ibv_cq *scq = NULL;

  struct rdma_addrinfo *_addrinfo;

  const uint32_t _max_inline_data;
  struct rdma_cm_id *listen_id = NULL;
  const char *_serverip;
  const uint32_t _max_send_wr;
  const uint32_t _max_recv_wr;
  const uint32_t _rdma_read_init;
  const uint32_t _rdma_read_target;
  const bool _server;
  const int _port;
  const bool with_shared_receive_completion;
  const bool with_shared_send_completion;

  const bool with_shared_receive;
  const bool single_recv_send_completion;
  const bool with_event_channels;

  struct rdma_event_channel *cm_channel;

 public:
  static struct ibv_context *ctxt;
  static struct ibv_pd *pd;

  RDMA_COM(uint32_t max_inline_data, uint32_t max_send_wr, uint32_t max_recv_wr,
           uint32_t rdma_read_init, uint32_t rdma_read_target, int port,
           const char *serverip, bool with_shared_receive_completion = false,
           bool with_shared_send_completion = false,
           bool with_shared_receive = false,
           bool single_recv_send_completion = false,
           bool with_event_channels = false)
      : _max_inline_data(max_inline_data),
        _serverip(serverip),
        _max_send_wr(max_send_wr),
        _max_recv_wr(max_recv_wr),
        _rdma_read_init(rdma_read_init),
        _rdma_read_target(rdma_read_target),
        _server(serverip == NULL),
        _port(port),
        with_shared_receive_completion(with_shared_receive_completion),
        with_shared_send_completion(with_shared_send_completion),
        with_shared_receive(with_shared_receive),
        single_recv_send_completion(single_recv_send_completion),
        with_event_channels(with_event_channels) {
    this->cm_channel = rdma_create_event_channel();

    if (this->cm_channel == NULL) {
      perror(" rdma_create_event_channel failed\n");
      exit(1);
    }

    if (_server) {
      if (this->ctxt == NULL) {
        //    struct ibv_device* dev = ctx_find_dev(NULL);
        //  this->ctxt = ibv_open_device(dev);
        struct ibv_context **devices = rdma_get_devices(NULL);
        this->ctxt = devices[0];
      }

      if (this->pd == NULL) {
        this->pd = ibv_alloc_pd(this->ctxt);
      }
    }

    struct rdma_addrinfo hints;
    memset(&hints, 0, sizeof(hints));

    hints.ai_port_space = RDMA_PS_TCP;
    hints.ai_family = AF_INET;

    if (_server) {
      hints.ai_flags = RAI_PASSIVE;
    }

    char strport[7] = "";
    sprintf(strport, "%d", _port);

    int rc = rdma_getaddrinfo(const_cast<char *>(_serverip), strport, &hints,
                              &_addrinfo);

    if (rc < 0) {
      text(log_fp, "rdma_getaddrinfo: %s\n", strerror(errno));
      exit(1);
    }

    if (_server) {
      rc = rdma_create_id(this->cm_channel, &listen_id, NULL, RDMA_PS_TCP);
      if (rc) {
        perror("Failed to create RDMA CM server control ID.");
        exit(1);
      }

      rc = rdma_bind_addr(listen_id, _addrinfo->ai_src_addr);
      if (rc) {
        perror("Failed to bind RDMA CM address on the server.");
        exit(1);
      }

      rc = rdma_listen(listen_id, 2);
      if (rc) {
        perror("rdma_listen");
        exit(1);
      }

    } else {
      text(log_fp,
           "\t[RDMA_COM] New connection as a client to IP %s at port %u \n",
           serverip, _port);
    }
    text(
        log_fp,
        "\t\tMax send wr: %u \n\t\tMax recv wr: %u \n\t\tMax_inline_data: %u\n",
        max_send_wr, max_recv_wr, max_inline_data);
  }

  struct ibv_device *ctx_find_dev(const char *ib_devname) {
    int num_of_device;
    struct ibv_device **dev_list;
    struct ibv_device *ib_dev = NULL;

    dev_list = ibv_get_device_list(&num_of_device);

    if (num_of_device <= 0) {
      fprintf(stderr, " Did not detect devices \n");
      fprintf(stderr, " If device exists, check if driver is up\n");
      return NULL;
    }

    if (!ib_devname) {
      ib_dev = dev_list[0];
      if (!ib_dev) {
        fprintf(stderr, "No IB devices found\n");
        exit(1);
      }
    } else {
      for (; (ib_dev = *dev_list); ++dev_list)
        if (!strcmp(ibv_get_device_name(ib_dev), ib_devname)) break;
      if (!ib_dev) fprintf(stderr, "IB device %s not found\n", ib_devname);
    }
    return ib_dev;
  }

  shared_connection_info get_shared_info() {
    shared_connection_info sci;
    sci.srq = this->srq;

    sci.receive_channel = this->receive_channel;
    sci.rcq = this->rcq;

    sci.send_channel = this->send_channel;
    sci.scq = this->scq;
    return sci;
  }

  void set_shared_info(shared_connection_info sci) {
    this->srq = sci.srq;
    this->receive_channel = sci.receive_channel;
    this->rcq = sci.rcq;

    this->send_channel = sci.send_channel;
    this->scq = sci.scq;
  }

  Connection *get_connection(uint32_t sge_size = 1) {
    assert(!_server);  // only client calls it

    struct rdma_cm_id *id = get_connection_cm(sge_size);

    Connection *newcon = new Connection(id, _max_inline_data, _max_recv_wr,
                                        _max_send_wr, with_shared_receive);

    newcon->SetTargetQPN();

    assert((this->scq == NULL || newcon->id->qp->send_cq == this->scq) &&
           "send queue error");

    text(log_fp, "\t[RDMA_COM] EP is created\n");
    return newcon;
  }

  int create_shared(uint32_t threads = 0) {
    if (with_shared_receive_completion) {
      if (with_event_channels && this->receive_channel == NULL) {
        this->receive_channel = ibv_create_comp_channel(this->ctxt);
      }

      if (this->rcq == NULL) {
        this->rcq = ibv_create_cq(this->ctxt, this->_max_recv_wr, NULL,
                                  this->receive_channel, 0);
      }
    }

    if (with_shared_send_completion) {
      if (single_recv_send_completion) {
        this->scq = this->rcq;
        this->send_channel = this->receive_channel;

      } else {
        if (with_event_channels && this->send_channel == NULL) {
          this->send_channel = ibv_create_comp_channel(this->ctxt);
        }

        if (this->scq == NULL) {
          this->scq = ibv_create_cq(this->ctxt, this->_max_send_wr, NULL,
                                    this->send_channel, 0);
        }
      }
    }

    if (with_shared_receive) {
      if (this->srq == NULL) {
        struct ibv_srq_init_attr srqattr;
        memset(&srqattr, 0, sizeof(ibv_srq_init_attr));
        srqattr.attr.max_wr = _max_recv_wr;
        srqattr.attr.max_sge = 1;
        this->srq = ibv_create_srq(this->pd, &srqattr);
      }
    }

    return 0;
  }

  int create_qp(struct rdma_cm_id *cm_id, uint32_t sge_size) {
    if (this->ctxt == NULL) {
      //    struct ibv_device* dev = ctx_find_dev(NULL);
      //  this->ctxt = ibv_open_device(dev);
      //          struct ibv_context ** devices = rdma_get_devices(NULL);
      //        this->ctxt =  devices[0];
      this->ctxt = cm_id->verbs;
    }

    if (this->pd == NULL) {
      this->pd = ibv_alloc_pd(this->ctxt);
    }

    struct ibv_cq *rcq = NULL;
    struct ibv_cq *scq = NULL;
    struct ibv_srq *srq = NULL;
    struct ibv_comp_channel *receive_channel = NULL;
    struct ibv_comp_channel *send_channel = NULL;

    if (with_shared_receive_completion) {
      rcq = this->rcq;
      receive_channel = this->receive_channel;

    } else {
      if (with_event_channels) {
        receive_channel = ibv_create_comp_channel(this->ctxt);
      }
      rcq = ibv_create_cq(this->ctxt, _max_recv_wr, NULL, receive_channel, 0);
    }

    assert(rcq);

    if (with_shared_send_completion) {
      send_channel = this->send_channel;
      scq = this->scq;

    } else {
      if (single_recv_send_completion) {
        scq = rcq;
        send_channel = receive_channel;

      } else {
        if (with_event_channels) {
          send_channel = ibv_create_comp_channel(this->ctxt);
        }
        scq = ibv_create_cq(this->ctxt, this->_max_send_wr, NULL, send_channel,
                            0);
      }
    }

    if (with_shared_receive) {
      srq = this->srq;
    }

    struct ibv_qp_init_attr attr;

    memset(&attr, 0, sizeof(struct ibv_qp_init_attr));
    attr.send_cq = scq;
    attr.recv_cq = rcq;
    attr.cap.max_send_wr = _max_send_wr;
    attr.cap.max_send_sge = sge_size;
    attr.cap.max_inline_data = this->_max_inline_data;

    if (this->with_shared_receive) {
      attr.srq = srq;
      attr.cap.max_recv_wr = 0;
      attr.cap.max_recv_sge = 0;
    } else {
      attr.srq = NULL;
      attr.cap.max_recv_wr = this->_max_recv_wr;
      attr.cap.max_recv_sge = 1;
    }

    attr.qp_type = IBV_QPT_RC;

    if (rdma_create_qp(cm_id, this->pd, &attr)) {
      perror("Couldn't create rdma QP \n");
      exit(1);
    }

    return 0;
  }

  struct rdma_cm_id *get_connection_cm(uint32_t sge_size = 1) {
    struct rdma_cm_id *cm_id;
    struct rdma_cm_event *event;

    if (rdma_create_id(cm_channel, &cm_id, NULL, RDMA_PS_TCP)) {
      perror("rdma_create_id failed\n");
      exit(1);
    }

    int rc = rdma_resolve_addr(cm_id, _addrinfo->ai_src_addr,
                               _addrinfo->ai_dst_addr, 2000);

    if (rc) {
      perror("Failed to resolve RDMA CM address.");
      exit(1);
    }

    int notconnected = 1;
    while (notconnected) {
      if (rdma_get_cm_event(cm_channel, &event)) {
        perror("rdma_get_cm_events failed\n");
        exit(1);
      }

      assert(event->id == cm_id && "Unexpected comletion event");

      if (event->event == RDMA_CM_EVENT_ADDR_RESOLVED) {
        rc = rdma_resolve_route(cm_id, 2000);
        if (rc) {
          perror("rdma_resolve_route failed\n");
          exit(1);
        }
      }

      if (event->event == RDMA_CM_EVENT_ROUTE_RESOLVED) {
        // connect

        rc = create_qp(cm_id, sge_size);
        if (rc) {
          perror("rdma_resolve_route failed\n");
          exit(1);
        }

        struct rdma_conn_param conn_param;
        memset(&conn_param, 0, sizeof(conn_param));

        conn_param.responder_resources = this->_rdma_read_target;
        conn_param.initiator_depth = this->_rdma_read_init;
        conn_param.retry_count = 3;      // TODO
        conn_param.rnr_retry_count = 3;  // TODO

        rc = rdma_connect(cm_id, &conn_param);
        if (rc) {
          perror("rdma_connect");
          exit(1);
        }
      }

      if (event->event == RDMA_CM_EVENT_ESTABLISHED) {
        // connect
        text(log_fp, "Connection established.\n");
        notconnected = 0;
      }

      rdma_ack_cm_event(event);
      // break;
    }

    return cm_id;
  }

  struct rdma_cm_id *accept_connection_cm(uint32_t sge_size = 1) {
    struct rdma_cm_id *cm_id = NULL;
    struct rdma_cm_event *event;
    int rc;

    int retry = 10;

    int notconnected = 1;
    while (notconnected && retry >= 0) {
      if (rdma_get_cm_event(cm_channel, &event)) {
        perror("rdma_get_cm_events failed\n");
        // exit(1);
        retry--;
        rdma_ack_cm_event(event);
        continue;
      }

      text(log_fp, "event %u\n", event->event);

      if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST) {
        cm_id = event->id;

        rc = create_qp(cm_id, sge_size);
        if (rc) {
          perror("rdma_resolve_route failed\n");
          exit(1);
        }

        struct rdma_conn_param conn_param;
        memset(&conn_param, 0, sizeof(conn_param));

        conn_param.responder_resources = this->_rdma_read_target;
        conn_param.initiator_depth = this->_rdma_read_init;
        conn_param.retry_count = 3;      // TODO
        conn_param.rnr_retry_count = 3;  // TODO

        rc = rdma_accept(cm_id, &conn_param);
        if (rc) {
          perror("rdma_accept failed\n");
          exit(1);
        }

        notconnected = 0;
      }

      if (event->event == RDMA_CM_EVENT_ESTABLISHED) {
        // connect
        text(log_fp, "Connection established.\n");
        notconnected = 0;
      }

      rdma_ack_cm_event(event);
    }

    return cm_id;
  }

  struct rdma_cm_id *accept_connection_cm_blocking(uint32_t sge_size = 1) {
    struct rdma_cm_id *cm_id = NULL;

    int rc;

    rc = rdma_get_request(this->listen_id, &cm_id);
    if (rc) {
      text(log_fp, "Error rdma get request\n");
      return NULL;
    }

    rc = create_qp(cm_id, sge_size);
    if (rc) {
      perror("rdma_resolve_route failed\n");
      exit(1);
    }

    struct rdma_conn_param conn_param;
    memset(&conn_param, 0, sizeof(conn_param));

    conn_param.responder_resources = this->_rdma_read_target;
    conn_param.initiator_depth = this->_rdma_read_init;
    conn_param.retry_count = 3;      // TODO
    conn_param.rnr_retry_count = 3;  // TODO

    rc = rdma_accept(cm_id, &conn_param);
    if (rc) {
      perror("rdma_accept failed\n");
      exit(1);
    }

    return cm_id;
  }

  int get_listen_fd() {
    assert(_server);  // only server calls it

    assert(this->cm_channel != NULL);
    int options = fcntl(this->cm_channel->fd, F_GETFL, 0);

    if (fcntl(this->cm_channel->fd, F_SETFL, options | O_NONBLOCK)) {
      perror("[RDMA_COM] cannot set server_client to non-blocking mode");
      exit(1);
      return 0;
    }

    return this->cm_channel->fd;
  }

  Connection *accept_connection(uint32_t sge_size = 1, bool blocking = false) {
    assert(_server);  // only server calls it

    struct rdma_cm_id *cm_id = NULL;
    if (blocking) {
      cm_id = accept_connection_cm_blocking(sge_size);
    } else {
      cm_id = accept_connection_cm(sge_size);
    }
    if (cm_id) {
      text(log_fp, "\t\t Try to get connection request\n");
      Connection *newcon = new Connection(cm_id, _max_inline_data, _max_recv_wr,
                                          _max_send_wr, with_shared_receive);

      newcon->SetTargetQPN();
      text(log_fp, "\t\t EP is connected\n");

      return newcon;
    }
    return NULL;
  }

  ~RDMA_COM() {
    if (this->listen_id != NULL) {
      rdma_destroy_ep(this->listen_id);
      this->listen_id = NULL;
    }

    rdma_freeaddrinfo(_addrinfo);
  }

  SharedReceive *getSharedReceive() {
    SharedReceive *sc =
        new SharedReceive(this->pd, this->srq, this->receive_channel, this->rcq,
                          this->_max_recv_wr);
    return sc;
  }

  SharedSend *getSharedSend() {
    SharedSend *sc =
        new SharedSend(this->send_channel, this->scq, this->_max_send_wr);
    return sc;
  }
};

struct ibv_pd *RDMA_COM::pd = NULL;
struct ibv_context *RDMA_COM::ctxt = NULL;
