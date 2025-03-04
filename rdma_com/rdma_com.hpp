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

  inline int 
  recv_check(struct ibv_wc *wc, int num = 1) {
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

    hints.ai_port_space = RDMA_PS_TCP;//指示正在使用的 RDMA 端口空间
    //对于 RDMA_PS_TCP 类型的 rdma_cm_id，rdma_connect会发起到远程目标的连接请求。
    hints.ai_family = AF_INET; //指定源和目标的地址族 地址

    if (_server) {
      hints.ai_flags = RAI_PASSIVE;//表示使用结果 在连接的被动或监听端
    }

    char strport[7] = "";
    sprintf(strport, "%d", _port);
    //函数 rdma_getaddrinfo _ 解析目的节点和服务地址并返回信息 这是建立通信所必需的。 该功能提供 RDMA 功能等同于 getaddrinfo. 
    int rc = rdma_getaddrinfo(const_cast<char *>(_serverip), strport, &hints,
                              &_addrinfo);

    if (rc < 0) {
      text(log_fp, "rdma_getaddrinfo: %s\n", strerror(errno));
      exit(1);
    }

    if (_server) {
      //绑定出cm_channel 到 cm_id
      rc = rdma_create_id(this->cm_channel, &listen_id, NULL, RDMA_PS_TCP);
      if (rc) {
        perror("Failed to create RDMA CM server control ID.");
        exit(1);
      }
//rdma_bind_addr 函数将源地址与 rdma_cm_id 标识符相关联.如果 rdma_cm_id 标识符具有本地地址，则该标识符也具有本地 RDMA 设备
      rc = rdma_bind_addr(listen_id, _addrinfo->ai_src_addr);
      if (rc) {
        perror("Failed to bind RDMA CM address on the server.");
        exit(1);
      }
//rdma_listen函数为传入的连接请求发起侦听操作。监听操作仅限于本地绑定的源地址。
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
//question:使用共享的receive_channel,如何初始化的
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
//共享rcq，即srq
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
//rdma_resolve_addr 函数将目标地址和可选源地址从 IP 地址解析为RDMA地址。  如果成功，则指定的 rdma_cm_id 标识符与本地设备相关联。

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
//assert判断是不是event关联的cm_id
      assert(event->id == cm_id && "Unexpected completion event");

      if (event->event == RDMA_CM_EVENT_ADDR_RESOLVED) {
        //rdma_resolve_route 函数将 RDMA 路由解析到目标地址以建立连接。  必须通过运行 rdma_resolve_addr 子例程来解析目标地址。
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
      //question:event是怎么来的，怎么到cm_channel中的
      if (rdma_get_cm_event(cm_channel, &event)) {
        perror("rdma_get_cm_events failed\n");
        // exit(1);
        retry--;
        rdma_ack_cm_event(event);
        continue;
      }

      text(log_fp, "event %u\n", event->event);
//指定与事件关联的rdma_cm标识符。如果 RDMA_CM_EVENT_CONNECT_REQUEST 是事件类型，则函数会引用一个新 ID 进行通信。
      if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST) {
        cm_id = event->id;

        rc = create_qp(cm_id, sge_size);
        if (rc) {
          perror("rdma_resolve_route failed\n");
          exit(1);
        }

        struct rdma_conn_param conn_param;
        memset(&conn_param, 0, sizeof(conn_param));
//指定本地端从远程端接受的未完成远程直接内存访问 (RDMA) 读取操作的最大数量.此属性仅适用于RDMA_PS_TCP事件
        conn_param.responder_resources = this->_rdma_read_target;
//指定本地端必须读取到远程端的最大未完成 RDMA 读取操作数。此属性仅适用于RDMA_PS_TCP事件
        conn_param.initiator_depth = this->_rdma_read_init;
        conn_param.retry_count = 3;      // TODO
//指定在收到接收方未就绪 （RNR） 错误后，在连接上尝试来自远程对等方的发送操作的最大次数。
        conn_param.rnr_retry_count = 3;  // TODO
//rdma_accept 函数用于接受连接查找请求
/*     rdma_accept 操作不会在侦听的 rdma_cm_id 标识符上调用。  rdma_listen 操作运行后，您必须等待连接请求事件发生。
     rdma_cm_id 标识符是由类似于新套接字的连接请求事件创建的，但 rdma_cm_id 标识符与特定的 RDMA 设备相关联。  在新的 rdma_cm_id 标识符上调用 rdma_accept 操作。*/
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


struct UDConnection {
  struct rdma_cm_id *id;
  const uint32_t max_inline_data;
  const uint32_t max_recv_size;
  const uint32_t max_send_size;
  const bool with_shared_receive;
  uint32_t target_qp_num;


UDconnection(struct rdma_cm_id *id, uint32_t max_inline_data,
             uint32_t max_recv_size, uint32_t max_send_size,
             bool with_shared_receive = false): id(id),
        max_inline_data(max_inline_data),
        max_recv_size(max_recv_size),
        max_send_size(max_send_size),
        with_shared_receive(with_shared_receive) {}

int get_cm_event(struct rdma_event_channel *channel,
                 enum rdma_cm_event_type type,
                 struct rdma_cm_event **out_ev)
{
    int ret = 0;
    struct rdma_cm_event *event = NULL;
    ret = rdma_get_cm_event(channel, &event);
    if (ret)
    {
        VERB_ERR("rdma_resolve_addr", ret);
        return -1;
    }
    /* Verify the event is the expected type */
    if (event->event != type)
    {
        printf("event: %s, status: %d\n",
               rdma_event_str(event->event), event->status);
        ret = -1;
    }
    /* Pass the event back to the user if requested */
    if (!out_ev)
        rdma_ack_cm_event(event);
    else
        *out_ev = event;
    return ret;
}

int resolve_addr(struct context *ctx)
{
    int ret;
    struct rdma_addrinfo *bind_rai = NULL;
    struct rdma_addrinfo *mcast_rai = NULL;
    struct rdma_addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_port_space = RDMA_PS_UDP;
    if (ctx->bind_addr)
    {
        hints.ai_flags = RAI_PASSIVE;
        ret = rdma_getaddrinfo(ctx->bind_addr, NULL, &hints, &bind_rai);
        if (ret)
        {
            VERB_ERR("rdma_getaddrinfo (bind)", ret);
            return ret;
        }
    }
    hints.ai_flags = 0;
    ret = rdma_getaddrinfo(ctx->mcast_addr, NULL, &hints, &mcast_rai);
    if (ret)
    {
        VERB_ERR("rdma_getaddrinfo (mcast)", ret);
        return ret;
    }
    if (ctx->bind_addr)
    {
        /* bind to a specific adapter if requested to do so */
        ret = rdma_bind_addr(ctx->id, bind_rai->ai_src_addr);
        if (ret)
        {
            VERB_ERR("rdma_bind_addr", ret);
            return ret;
        }
        /* A PD is created when we bind. Copy it to the context so it can
         * be used later on */
        ctx->pd = ctx->id->pd;
    }
    ret = rdma_resolve_addr(ctx->id, (bind_rai) ? bind_rai->ai_src_addr : NULL,
                            mcast_rai->ai_dst_addr, 2000);
    if (ret)
    {
        VERB_ERR("rdma_resolve_addr", ret);
        return ret;
    }
    ret = get_cm_event(ctx->channel, RDMA_CM_EVENT_ADDR_RESOLVED, NULL);
    if (ret)
    {
        return ret;
    }
    memcpy(&ctx->mcast_sockaddr,
           mcast_rai->ai_dst_addr,
           sizeof(struct sockaddr));
    return 0;
}

int create_resources(struct context *ctx)
{
    int ret, buf_size;
    struct ibv_qp_init_attr attr;
    memset(&attr, 0, sizeof(attr));
    /* If we are bound to an address, then a PD was already allocated
     * to the CM ID */
    if (!ctx->pd)
    {
        ctx->pd = ibv_alloc_pd(ctx->id->verbs);
        if (!ctx->pd)
        {
            VERB_ERR("ibv_alloc_pd", -1);
            return ret;
        }
    }
    ctx->cq = ibv_create_cq(ctx->id->verbs, 2, 0, 0, 0);
    if (!ctx->cq)
    {
        VERB_ERR("ibv_create_cq", -1);
        return ret;
    }
    attr.qp_type = IBV_QPT_UD;
    attr.send_cq = ctx->cq;
    attr.recv_cq = ctx->cq;
    attr.cap.max_send_wr = ctx->msg_count;
    attr.cap.max_recv_wr = ctx->msg_count;
    attr.cap.max_send_sge = 1;
    attr.cap.max_recv_sge = 1;
    ret = rdma_create_qp(ctx->id, ctx->pd, &attr);
    if (ret)
    {
        VERB_ERR("rdma_create_qp", ret);
        return ret;
    }
    /* The receiver must allow enough space in the receive buffer for
     * the GRH */
    buf_size = ctx->msg_length + (ctx->sender ? 0 : sizeof(struct ibv_grh));
    ctx->buf = calloc(1, buf_size);
    memset(ctx->buf, 0x00, buf_size);
    /* Register our memory region */
    ctx->mr = rdma_reg_msgs(ctx->id, ctx->buf, buf_size);
    if (!ctx->mr)
    {
        VERB_ERR("rdma_reg_msgs", -1);
        return -1;
    }
    return 0;
}
void destroy_resources(struct context *ctx)
{
    if (ctx->ah)
        ibv_destroy_ah(ctx->ah);
    if (ctx->id->qp)
        rdma_destroy_qp(ctx->id);
    if (ctx->cq)
        ibv_destroy_cq(ctx->cq);
    if (ctx->mr)
        rdma_dereg_mr(ctx->mr);
    if (ctx->buf)
        free(ctx->buf);
    if (ctx->pd && ctx->id->pd == NULL)
        ibv_dealloc_pd(ctx->pd);
    rdma_destroy_id(ctx->id);
}

int post_send(struct context *ctx)
{
    int ret;
    struct ibv_send_wr wr, *bad_wr;
    struct ibv_sge sge;
    
   // memset(ctx->buf, 0x12, ctx->msg_length); /* set the data to non-zero */
    sge.length = ctx->msg_length;
    sge.lkey = ctx->mr->lkey;
    sge.addr = (uint64_t)ctx->buf;
    /* Multicast requires that the message is sent with immediate data
     * and that the QP number is the contents of the immediate data */
    wr.next = NULL;
    wr.sg_list = &sge;
    wr.num_sge = 1;
    wr.opcode = IBV_WR_SEND_WITH_IMM;
    wr.send_flags = IBV_SEND_SIGNALED;
    wr.wr_id = 0;
    wr.imm_data = htonl(ctx->id->qp->qp_num);
    wr.wr.ud.ah = ctx->ah;
    wr.wr.ud.remote_qpn = ctx->remote_qpn;
    wr.wr.ud.remote_qkey = ctx->remote_qkey;
    ret = ibv_post_send(ctx->id->qp, &wr, &bad_wr);
    if (ret)
    {
        VERB_ERR("ibv_post_send", ret);
        return -1;
    }
    return 0;
}

int get_completion(struct context *ctx)
{
    int ret;
    struct ibv_wc wc;
    do
    {
        ret = ibv_poll_cq(ctx->cq, 1, &wc);
        if (ret < 0)
        {
            VERB_ERR("ibv_poll_cq", ret);
            return -1;
        }
    } while (ret == 0);
    if (wc.status != IBV_WC_SUCCESS)
    {
        printf("work completion status %s\n",
               ibv_wc_status_str(wc.status));
        return -1;
    }
    return 0;
}
}

struct UDConnection :struct Connection{
    UDConnection(struct rdma_cm_id *id, uint32_t max_inline_data,
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

} 