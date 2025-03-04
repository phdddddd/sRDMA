#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <time.h>
#include <endian.h>
#include <infiniband/verbs.h>

enum {
    PINGPONG_RECV_WRID = 1,
    PINGPONG_SEND_WRID = 2,
};

static int page_size;

struct pingpong_context {
    struct ibv_context  *context;
    struct ibv_comp_channel *channel;
    struct ibv_pd       *pd;
    struct ibv_mr       *mr;
    struct ibv_cq       *cq;
    struct ibv_qp       *qp;
    struct ibv_ah       *ah;
    char         *buf;
    int          size;
    int          send_flags;
    int          rx_depth;
    int          pending;
    struct ibv_port_attr     portinfo;
};

struct pingpong_dest {
    int lid;
    int qpn;
    int psn;
    union ibv_gid gid;
};

void
wire_gid_to_gid(const char *wgid, union ibv_gid *gid)
{
    char tmp[9];
    __be32 v32;
    int i;
    uint32_t tmp_gid[4];

    for (tmp[8] = 0, i = 0; i < 4; ++i) {
        memcpy(tmp, wgid + i * 8, 8);
        sscanf(tmp, "%x", &v32);
        tmp_gid[i] = be32toh(v32);
    }
    memcpy(gid, tmp_gid, sizeof(*gid));
}

void
gid_to_wire_gid(const union ibv_gid *gid, char wgid[])
{
    uint32_t tmp_gid[4];
    int i;

    memcpy(tmp_gid, gid, sizeof(tmp_gid));
    for (i = 0; i < 4; ++i)
        sprintf(&wgid[i * 8], "%08x", htobe32(tmp_gid[i]));
}

static struct pingpong_context *
init_ctx(struct ibv_device *ib_dev, int size, int port)
{
    struct pingpong_context *ctx = NULL;

    ctx = malloc(sizeof(*ctx));
    if(!ctx) {
        printf("malloc ctx error\n");
        return NULL;
    }

    ctx->size = size;
    ctx->send_flags = IBV_SEND_SIGNALED;
    ctx->buf = memalign(page_size, size + 40);
    if(!ctx->buf) {
        printf("ctx->buf malloc error\n");
        goto clean_ctx;
    }

    memset(ctx->buf, 0, size + 40);
    strncpy(ctx->buf + 40, "viscore server", sizeof "visocre server");

    ctx->context = ibv_open_device(ib_dev);
    if(!ctx->context) {
        printf("ctx->context error, %s\n", ibv_get_device_name(ib_dev));
        goto clean_buffer;
    }

    {
        /*查询端口 mtu大小*/
        struct ibv_port_attr port_info = {};
        int mtu;
        if(ibv_query_port(ctx->context, port, &port_info)) {
            printf("ibv_query_port error\n");
            goto clean_device;
        }
        mtu = 1 << (port_info.active_mtu + 7);
        if (size > mtu) {
            printf("Requested size larger than port MTU (%d)\n", mtu);
            goto clean_device;
        }
    }

    ctx->channel = ibv_create_comp_channel(ctx->context);
    if(!ctx->channel) {
        printf("ibv_create_comp_channel error\n");
        goto clean_device;
    }

    ctx->pd = ibv_alloc_pd(ctx->context);
    if(!ctx->pd) {
        printf("ibv_alloc_pd error\n");
        goto clean_comp_channel;
    }

    ctx->mr = ibv_reg_mr(ctx->pd, ctx->buf, size + 40, IBV_ACCESS_LOCAL_WRITE);
    if(!ctx->mr) {
        printf("ibv_reg_mr error\n");
        goto clean_pd;
    }

    ctx->cq = ibv_create_cq(ctx->context, 10, NULL, ctx->channel, 0);
    if(!ctx->cq) {
        printf("ibv_create_cq error\n");
        goto clean_mr;
    }

    {
        struct ibv_qp_attr attr;
        struct ibv_qp_init_attr init_attr = {
            .send_cq = ctx->cq,
            .recv_cq = ctx->cq,
            .cap     = {
                .max_send_wr  = 10,
                .max_recv_wr  = 10,
                .max_send_sge = 1,
                .max_recv_sge = 1
            },
            .qp_type = IBV_QPT_UD,
        };

        ctx->qp = ibv_create_qp(ctx->pd, &init_attr);
        if (!ctx->qp)  {
            printf("Couldn't create QP\n");
            goto clean_cq;
        }

        ibv_query_qp(ctx->qp, &attr, IBV_QP_CAP, &init_attr);
        if (init_attr.cap.max_inline_data >= size) {
            ctx->send_flags |= IBV_SEND_INLINE;
        }
    }

    {
        struct ibv_qp_attr attr = {
            .qp_state        = IBV_QPS_INIT,
            .pkey_index      = 0,
            .port_num        = port,
            .qkey            = 0x11111111
        };
        /*修改QP状态-->IBV_QPS_INIT*/
        if (ibv_modify_qp(ctx->qp, &attr,
                  IBV_QP_STATE              |
                  IBV_QP_PKEY_INDEX         |
                  IBV_QP_PORT               |
                  IBV_QP_QKEY)) {
            printf("Failed to modify QP to INIT\n");
            goto clean_qp;
        }
    }
    return ctx;
clean_qp:
    ibv_destroy_qp(ctx->qp);
clean_cq:
    ibv_destroy_cq(ctx->cq);
clean_mr:
    ibv_dereg_mr(ctx->mr);
clean_pd:
    ibv_dealloc_pd(ctx->pd);
clean_comp_channel:
    if (ctx->channel)
        ibv_destroy_comp_channel(ctx->channel);
clean_device:
    ibv_close_device(ctx->context);
clean_buffer:
    free(ctx->buf);
clean_ctx:
    free(ctx);
    return NULL;
}

static int 
close_ctx(struct pingpong_context *ctx)
{
    if (ibv_destroy_qp(ctx->qp)) {
        fprintf(stderr, "Couldn't destroy QP\n");
        return 1;
    }

    if (ibv_destroy_cq(ctx->cq)) {
        fprintf(stderr, "Couldn't destroy CQ\n");
        return 1;
    }

    if (ibv_dereg_mr(ctx->mr)) {
        fprintf(stderr, "Couldn't deregister MR\n");
        return 1;
    }

    if (ibv_destroy_ah(ctx->ah)) {
        fprintf(stderr, "Couldn't destroy AH\n");
        return 1;
    }

    if (ibv_dealloc_pd(ctx->pd)) {
        fprintf(stderr, "Couldn't deallocate PD\n");
        return 1;
    }

    if (ctx->channel) {
        if (ibv_destroy_comp_channel(ctx->channel)) {
            fprintf(stderr, "Couldn't destroy completion channel\n");
            return 1;
        }
    }

    if (ibv_close_device(ctx->context)) {
        fprintf(stderr, "Couldn't release context\n");
        return 1;
    }
    free(ctx->buf);
    free(ctx);
    return 0;
}

static int
post_recv(struct pingpong_context *ctx)
{
    struct ibv_sge list = {
        .addr   = (uintptr_t) ctx->buf,
        .length = ctx->size + 40,
        .lkey   = ctx->mr->lkey
    };
    struct ibv_recv_wr wr = {
        .wr_id      = PINGPONG_RECV_WRID,
        .sg_list    = &list,
        .num_sge    = 1,
        .next       = NULL,
    };
    struct ibv_recv_wr *bad_wr;
    ibv_post_recv(ctx->qp, &wr, &bad_wr);
    return 0;
}

static int
post_send(struct pingpong_context *ctx, uint32_t qpn)
{
    struct ibv_sge list = {
        .addr   = (uintptr_t) ctx->buf + 40,
        .length = ctx->size,
        .lkey   = ctx->mr->lkey
    };
    struct ibv_send_wr wr = {
        .wr_id      = PINGPONG_SEND_WRID,
        .sg_list    = &list,
        .num_sge    = 1,
        .opcode     = IBV_WR_SEND,
        .send_flags = ctx->send_flags,
        .wr         = {
            .ud = {
                 .ah          = ctx->ah,
                 .remote_qpn  = qpn,
                 .remote_qkey = 0x11111111
             }
        }
    };
    struct ibv_send_wr *bad_wr;
    return ibv_post_send(ctx->qp, &wr, &bad_wr);
}

static int
connect_ctx(struct pingpong_context *ctx, int port, int my_psn,
    int sl, struct pingpong_dest *dest, int sgid_idx)
{
    struct ibv_ah_attr ah_attr = {
        .is_global     = 0,
        .dlid          = dest->lid,
        .sl            = sl,
        .src_path_bits = 0,
        .port_num      = port
    };

    struct ibv_qp_attr attr = {
        .qp_state       = IBV_QPS_RTR
    };

    if (ibv_modify_qp(ctx->qp, &attr, IBV_QP_STATE)) {
        fprintf(stderr, "Failed to modify QP to RTR\n");
        return 1;
    }

    attr.qp_state = IBV_QPS_RTS;
    attr.sq_psn   = my_psn;

    if (ibv_modify_qp(ctx->qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN)) {
        fprintf(stderr, "Failed to modify QP to RTS\n");
        return 1;
    }

    if (dest->gid.global.interface_id) {
        ah_attr.is_global = 1;
        ah_attr.grh.hop_limit = 1;
        ah_attr.grh.dgid = dest->gid;
        ah_attr.grh.sgid_index = sgid_idx;
    }

    ctx->ah = ibv_create_ah(ctx->pd, &ah_attr);
    if (!ctx->ah) {
        fprintf(stderr, "Failed to create AH\n");
        return 1;
    }
    return 0;
}

static struct pingpong_dest *
server(struct pingpong_context *ctx, int ib_port, int port, 
    int sl, const struct pingpong_dest *my_dest, int sgid_idx)
{
    char gid[33];
    int n = 0;
    int sockfd = -1, connfd = -1;
    struct sockaddr_in serv_addr;
    struct pingpong_dest *rem_dest = NULL;
    char msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        printf("socket error\n");
        return NULL;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port); 

    bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    if(listen(sockfd, 1) < 0) {
        printf("accept error\n");
        goto out;
    }

    connfd = accept(sockfd, (struct sockaddr*)NULL, NULL);
    if(connfd < 0) {
        printf("accept error\n");
        return NULL;
    }

    close(sockfd);
    n = read(connfd, msg, sizeof(msg));
    if(n != sizeof(msg)) {
        printf("n != sizeof(msg) error\n");
        goto out;
    }

    rem_dest = malloc(sizeof *rem_dest);
    if (!rem_dest) {
        printf("malloc rem_dest error \n");
        goto out;
    }
    /*从msg里面读取数据，按照一定格式写入rem_dest的各个变量里*/
    sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn, &rem_dest->psn, gid);
    /*把gid的值写入rem_dest->gid*/
    wire_gid_to_gid(gid, &rem_dest->gid);
    /*创建AH*/
    if(connect_ctx(ctx, ib_port, my_dest->psn, 
        sl, rem_dest, sgid_idx)) {
        printf("connect_ctx error\n");
        free(rem_dest);
        rem_dest = NULL;
        goto out;
    }

    gid_to_wire_gid(&my_dest->gid, gid);
    /*把值按一定的格式写入msg*/
    sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn, my_dest->psn, gid);
    
    if(write(connfd, msg, sizeof(msg)) != sizeof(msg)) {
        printf("write error\n");
        free(rem_dest);
        rem_dest = NULL;
        goto out;
    }

    if(read(connfd, msg, sizeof(msg)) != sizeof "done") {
        printf("read error\n");
        free(rem_dest);
        rem_dest = NULL;
        goto out;
    }
out:
    close(connfd);
    return rem_dest;
}

int main(int argc, char **argv)
{
    struct ibv_device      **dev_list;
    struct ibv_device      *ib_dev;
    struct pingpong_context *ctx;
    struct pingpong_dest my_dest, *rem_dest;
    unsigned int             port = 18515;
    int                      ib_port = 1;
    int                      gidx = 2;
    int                      sl = 0;
    unsigned int             size = 500;
    char                     gid[33];

    srand48(getpid() * time(NULL));
    while (1) {
        int c;
        static struct option long_options[] = {
            { .name = "port",     .has_arg = 1, .val = 'p' },
            { .name = "ib-port",  .has_arg = 1, .val = 'i' },
            { .name = "size",     .has_arg = 1, .val = 's' },
            { .name = "sl",       .has_arg = 1, .val = 'l' },
            {}
        };

        c = getopt_long(argc, argv, "p:i:s:r:l", long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'p':
            port = strtol(optarg, NULL, 0);
            if (port > 65535) {
                return 1;
            }
            break;
        case 'i':
            ib_port = strtol(optarg, NULL, 0);
            if (ib_port < 1) {
                return 1;
            }
            break;
        case 's':
            size = strtoul(optarg, NULL, 0);
            break;
        case 'l':
            sl = strtol(optarg, NULL, 0);
            break;
        default:
            return 1;
        }
    }

    page_size = sysconf(_SC_PAGESIZE);
    dev_list = ibv_get_device_list(NULL);
    if(!dev_list){
        printf("ibv_get_device_list error\n");
        return -1;
    } else {
        ib_dev = *dev_list;
        if (!ib_dev) {
            fprintf(stderr, "No IB devices found\n");
            return 1;
        }
    }

    ctx = init_ctx(ib_dev, size, ib_port);
    if(!ctx){
        printf("init_ctx error\n");
        return -1;
    }

    post_recv(ctx);
    if(ibv_req_notify_cq(ctx->cq, 0)){
        printf("ibv_req_notify_cq error\n");
        return -1;
    }
    /*获取lid信息*/
    if(ibv_query_port(ctx->context, ib_port, &ctx->portinfo)){
        printf("ibv_query_port error\n");
        return -1;
    }

    my_dest.lid = ctx->portinfo.lid;
    my_dest.qpn = ctx->qp->qp_num;
    my_dest.psn = lrand48() & 0xffffff;

    /*得到my_dest.gid的值*/
    if (ibv_query_gid(ctx->context, ib_port, gidx, &my_dest.gid)) {
        printf("Could not get local gid for gid index %d\n", gidx);
        return -1;
    }

    /*将my_dest.gid的值转为点分十进制形式*/
    inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof(gid));
    printf("local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x: GID %s\n",
           my_dest.lid, my_dest.qpn, my_dest.psn, gid);

    rem_dest = server(ctx, ib_port, port, sl, &my_dest, gidx);
    if(!rem_dest){
        printf("server error\n");
        return -1;
    }

    inet_ntop(AF_INET6, &rem_dest->gid, gid, sizeof(gid));
    printf("remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
           rem_dest->lid, rem_dest->qpn, rem_dest->psn, gid);

    int event_num = 0;
    while (event_num < 2) {
        struct ibv_cq *cq;
        struct ibv_wc wc;
        void *ex_ctx;

        ibv_get_cq_event(ctx->channel, &cq, &ex_ctx);
        ibv_ack_cq_events(cq, 1);
        event_num++;
        ibv_req_notify_cq(cq, 0);

        while(ibv_poll_cq(cq, 1, &wc)) {
            if(wc.status != IBV_WC_SUCCESS){
                printf("wc.status != IBV_WC_SUCCESS\n");
            }
            if(wc.opcode & IBV_WC_RECV) {
                printf("IBV_WC_RECV ok, %s\n", ctx->buf + 40);
                strncpy(ctx->buf + 40, "viscore server", sizeof "visocre server");
                if (post_send(ctx, rem_dest->qpn)) {
                    printf("Couldn't post send\n");
                    return 1;
                }
            }
            else if(wc.opcode == IBV_WC_SEND){
                printf("IBV_WC_SEND ok\n");
            }
        }
    }

    if(close_ctx(ctx)){
        printf("close_ctx error \n");
        return -1;
    }
    ibv_free_device_list(dev_list);
    free(rem_dest);
    return 0;
}
