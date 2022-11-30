#pragma once
#include <infiniband/verbs.h>
#include <atomic>
#include <fstream>
#include <iostream>
#include <unordered_map>
#include <utility>
#include <vector>
#include "../rdma_com/rdma_com.hpp"
#include "../thread/thread.hpp"
#include "../utilities/readerwriterqueue.h"
#include "generic_worker.hpp"
#include "secure_qp.hpp"

using namespace moodycamel;

struct request_t {
  uint32_t type;
  uint32_t len;
};

 
#define WRITE_OP 0
#define READ_OP 1

class RequestInitWorker : public GenericWorker {
 public:
  RequestInitWorker(uint32_t id, SequreQP* qp, uint64_t remote_addr,
                    uint32_t remote_rkey, uint32_t maxoutstand, uint32_t batch,
                    uint32_t recv_size, uint32_t send_size, region_t remregion)
      : id(id),
        qp(qp),
        remote_addr(remote_addr),
        remote_rkey(remote_rkey),
        made_measurements(0),
        maxoutstand(maxoutstand),
        outstanding(0),
        outstandingwqe(0),
        batch(batch),
        send_size(send_size),
        completions(0),
        remregion(remregion),
        minibatchcounter(0),
        q(1024) {
    receivemr = qp->reg_mem(4096);

    for (uint32_t i = 0; i < recv_size; i++) {
      qp->post_recv(receivemr, 1);
    }

    for (uint32_t i = 0; i < send_size; i++) {
      sendbuffers.push_back(qp->reg_mem(4096));
    }
    currentbuf = 0;

    if (this->remregion.begin != 0) {
      this->withremregion = &(this->remregion);
    } else {
      this->withremregion = NULL;
    }
  }

  ~RequestInitWorker() {
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

  ReaderWriterQueue<request_t>& get_queue();

  const uint32_t id;

  SequreQP* qp;
  const uint64_t remote_addr;
  const uint32_t remote_rkey;

  uint32_t made_measurements;

  const uint32_t maxoutstand;
  uint32_t outstanding;
  uint32_t outstandingwqe;
  const uint32_t batch;
  const uint32_t send_size;
  uint32_t completions;

  region_t remregion;
  region_t* withremregion;

  struct ibv_mr* receivemr;
  uint32_t wr_id = 10;

  std::vector<uint32_t> measurements;

  uint32_t minibatchcounter;

  ReaderWriterQueue<request_t> q;

  std::vector<struct ibv_mr*> sendbuffers;
  uint32_t currentbuf;
};

void RequestInitWorker::main_cb() {
  if (outstanding < maxoutstand && outstandingwqe < maxoutstand) {
    for (uint32_t i = 0; i < batch; i++) {
      request_t req;
      if (!q.try_dequeue(req)) {
        if (outstanding == 0 && this->id == 0) {
          std::raise(SIGINT);
        }
        break;
      }

      bool signaled = false;
      minibatchcounter++;
      if (minibatchcounter == batch) {
        signaled = true;
        outstanding += batch;
        outstandingwqe += batch;
        minibatchcounter = 0;
      }
      uint32_t len = req.len;
      if (req.type == WRITE_OP) {
        qp->Write(wr_id, (uint64_t)sendbuffers[currentbuf]->addr,
                  sendbuffers[currentbuf]->lkey, len, remote_addr, remote_rkey,
                  signaled, withremregion);
        currentbuf = (currentbuf + 1) % send_size;

      } else {
        qp->Read(wr_id, (uint64_t)receivemr->addr, receivemr->rkey, len,
                 remote_addr, remote_rkey, signaled, withremregion);
      }

      //            currentbuf = (currentbuf+1) % send_size;
      if (signaled) {  // only send batch
        break;
      }
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

void RequestInitWorker::sometimes_cb() {
  measurements.push_back(completions);
  // if(this->id==0)
  text(log_fp, "(%u) We have %u completions %u\n", this->id, completions,
       outstanding);
  //  printf("(%u) We have %u completions %u %u\n", this->id,
  //  completions,outstanding,outstandingwqe);
  completions = 0;
  made_measurements++;
}

ReaderWriterQueue<request_t>& RequestInitWorker::get_queue() {
  return std::ref(q);
}

class TraceReader : public GenericWorker {
 public:
  TraceReader(std::vector<ReaderWriterQueue<request_t>*> qvec, std::string name,
              uint32_t qsize)
      : current_worker(0),
        total_workers(qvec.size()),
        in(name, std::ios_base::in | std::ios_base::binary) {
    for (uint32_t i = 0; i < qvec.size(); i++) {
      workers.push_back(qvec[i]);
    }

    request_t req[batch];

    uint32_t preappend = qsize * total_workers * sizeof(request_t);
    uint32_t read = 0;
    uint32_t read_portion = batch * sizeof(request_t);

    while (in.good() && (qsize == 0)) {
      in.read((char*)&req[0], read_portion);

      uint32_t readelements = in.gcount() / sizeof(request_t);
      read += (readelements * sizeof(request_t));

      // printf("%u \n", readelements);
      for (uint32_t i = 0; i < readelements; i++) {
        //                printf("%u\n", req[i].len);
        workers[current_worker]->enqueue(req[i]);
        current_worker++;
        current_worker = current_worker % total_workers;
      }
    }
  }

  ~TraceReader() { in.close(); }

  void main_cb() override;
  void sometimes_cb() override;

  std::vector<ReaderWriterQueue<request_t>*> workers;

  uint32_t current_worker;
  const uint32_t total_workers;
  const uint32_t batch = 1024;

  std::ifstream in;
};

void TraceReader::main_cb() {
  request_t req[batch];

  if (in.good()) {
    in.read((char*)&req[0], batch * sizeof(request_t));

    uint32_t readelements = in.gcount() / sizeof(request_t);

    for (uint32_t i = 0; i < readelements; i++) {  // 1000 - batch

      bool succeeded = false;
      while (!succeeded) {
        succeeded = workers[current_worker]->try_enqueue(req[i]);
        current_worker++;
        current_worker = current_worker % total_workers;
      }
    }
  }
}

void TraceReader::sometimes_cb() {}
