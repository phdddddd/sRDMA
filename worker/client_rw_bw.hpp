#pragma once
#include <infiniband/verbs.h>
#include <atomic>
#include <unordered_map>
#include <utility>
#include <vector>
#include "../rdma_com/rdma_com.hpp"
#include "../thread/thread.hpp"
#include "generic_worker.hpp"
#include "secure_qp.hpp"

#define WRITE_TEST 1
#define READ_TEST 2

class ClientReadWriteWorker : public GenericWorker {
 public:
  ClientReadWriteWorker(uint8_t id, uint8_t readprob, SequreQP* qp,
                        uint64_t remote_addr, uint32_t remote_rkey,
                        uint32_t total_measurements, uint32_t maxoutstand,
                        uint32_t batch, uint32_t len, uint32_t recv_size,
                        uint32_t send_size, region_t remregion)
      : id(id),
        readprob(readprob),
        qp(qp),
        remote_addr(remote_addr),
        remote_rkey(remote_rkey),
        made_measurements(0),
        total_measurements(total_measurements),
        maxoutstand(maxoutstand),
        outstanding(0),
        outstandingwqe(0),
        batch(batch),
        len(len),
        send_size(send_size),
        completions(0),
        remregion(remregion) {
    receivemr = qp->reg_mem(4096);

    for (uint32_t i = 0; i < recv_size; i++) {
      qp->post_recv(receivemr, 1);
    }

    {
      uint32_t allocate = send_size * 4096;
      char* buf = (char*)aligned_alloc(4096, allocate);
      if (buf == NULL) {
        printf("[Error] Not enough memory to allocate  %u bytes \n", allocate);
        exit(1);
      }
      struct ibv_mr* originalmr = qp->reg_mem(buf, allocate);

      for (uint32_t i = 0; i < send_size; i++) {
        struct ibv_mr* mr = (struct ibv_mr*)malloc(sizeof(struct ibv_mr));
        *mr = *originalmr;
        mr->addr = (char*)(originalmr->addr) + 4096 * i;
        mr->length = 4096;
        sendbuffers.push_back(mr);
      }
    }

    currentbuf = 0;

    if (this->remregion.begin != 0) {
      this->withremregion = &(this->remregion);
    } else {
      this->withremregion = NULL;
    }
  }

  ~ClientReadWriteWorker() {
    for (uint32_t i = 0; i < measurements.size(); i++) {
      uint32_t count = measurements[i];
      info(log_fp, "%u ", count);
    }
    info(log_fp, "\n ");

    measurements.clear();

    delete qp;
  }

  void main_cb() override;
  void sometimes_cb() override;

  const uint8_t id;
  const uint8_t readprob;
  SequreQP* qp;
  const uint64_t remote_addr;
  const uint32_t remote_rkey;

  uint32_t made_measurements;
  const uint32_t total_measurements;
  const uint32_t maxoutstand;
  uint32_t outstanding;
  uint32_t outstandingwqe;
  const uint32_t batch;
  const uint32_t len;
  const uint32_t send_size;
  uint32_t completions;
  region_t remregion;

  region_t* withremregion;

  struct ibv_mr* receivemr;
  uint32_t wr_id = 10;

  std::vector<uint32_t> measurements;

  std::vector<struct ibv_mr*> sendbuffers;
  uint32_t currentbuf;
};

void ClientReadWriteWorker::main_cb() {
  if (made_measurements < total_measurements || total_measurements == 0) {
    if (maxoutstand > outstanding && outstandingwqe < maxoutstand) {
      for (uint32_t req = 0; req < batch - 1; req++) {
        if (rand() % 100 < readprob) {
          qp->Read(wr_id, (uint64_t)receivemr->addr, receivemr->rkey, len,
                   remote_addr, remote_rkey, false, withremregion);
        } else {
          qp->Write(wr_id, (uint64_t)sendbuffers[currentbuf]->addr,
                    sendbuffers[currentbuf]->lkey, len, remote_addr,
                    remote_rkey, false, withremregion);
          currentbuf = (currentbuf + 1) % send_size;
        }
      }
      if (rand() % 100 < readprob) {
        qp->Read(wr_id, (uint64_t)receivemr->addr, receivemr->rkey, len,
                 remote_addr, remote_rkey, true, withremregion);
      } else {
        qp->Write(wr_id, (uint64_t)sendbuffers[currentbuf]->addr,
                  sendbuffers[currentbuf]->lkey, len, remote_addr, remote_rkey,
                  true, withremregion);
        currentbuf = (currentbuf + 1) % send_size;
      }
      outstanding += batch;
      outstandingwqe += batch;
    }
  }

  struct ibv_wc wc;
  if (qp->poll_recv_cq(&wc) > 0) {
    completions += batch;
    outstanding -= batch;
    qp->post_recv(receivemr, 1);
  }

  if (qp->poll_send_cq(&wc) > 0) {
    outstandingwqe -= batch;
  }
}

void ClientReadWriteWorker::sometimes_cb() {
  measurements.push_back(completions);
  text(log_fp, "(%u) We have %u completions %u\n", this->id, completions,
       outstanding);
  completions = 0;
  made_measurements++;

  if (id == 0 && made_measurements >= total_measurements &&
      total_measurements != 0) {
    std::raise(SIGINT);
  }
}
