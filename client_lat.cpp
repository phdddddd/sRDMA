#include <chrono>  // std::chrono::seconds
#include <thread>  // std::this_thread::sleep_for
#include "utilities/cxxopts.hpp"
#include "utilities/timer.h"
#include "worker/TCPExchange.hpp"
#include "worker/secure_qp.hpp"

unsigned char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,  // 16
                       0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};  // 32

unsigned char pdkey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};  // 16

unsigned char mymemkey[] = {0x7e, 0x7e, 0x15, 0x16, 0x28, 0x7e,
                            0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                            0x09, 0xcf, 0x4f, 0x3c};  // 16

cxxopts::ParseResult parse(int argc, char *argv[]) {
  cxxopts::Options options(argv[0], "Secure QP latency test");
  options.positional_help("[optional args]").show_positional_help();

  try {
    std::stringstream stream;
    stream << "0x" << std::hex << IBV_HDR_HMAC_SHA2_256;
    std::string resultstr(stream.str());

    options.add_options()
    ("smartnic", "smartnic address",cxxopts::value<std::string>(), "IP")
    ("another", "Another address", cxxopts::value<std::string>(), "IP")
    ("drkey", "Use key derivation",cxxopts::value<bool>()->default_value("false"))
    ("psn", "Local send psn",cxxopts::value<uint32_t>()->default_value("123"),"N")
    ("crypto", "Protection algorithm",cxxopts::value<uint32_t>()->default_value(resultstr),"N")
    ("memkey", "Use key derivation for memory sub delegation",cxxopts::value<bool>()->default_value("false"))
    ("len", "Packet size",cxxopts::value<uint64_t>()->default_value(std::to_string(2048)),"N")
    ("num", "Number of measurements",cxxopts::value<uint64_t>()->default_value(std::to_string(100)),"N")
    ("o,output", "Output file", cxxopts::value<std::string>(),"FILE")
    ("help", "Print help");

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    return result;

  } catch (const cxxopts::OptionException &e) {
    std::cout << "error parsing options: " << e.what() << std::endl;
    std::cout << options.help({""}) << std::endl;
    exit(1);
  }
}

FILE *log_fp;

std::vector<uint64_t> measurements;

struct ibv_mr *mr;
struct ibv_mr *mr2;
uint32_t wr_id = 10;

struct ibv_wc wc;

unsigned long long g_timerfreq;
HRT_TIMESTAMP_T start, finish;
uint64_t latency;

SequreQP *qp;
exchange_params params = {0, 0, 0, 0};

region_t remregion = {0, 0, 0};

unsigned char *memkey = NULL;

void measure_read(uint32_t len, uint32_t N) {
  HRT_GET_TIMESTAMP(start);
  for (uint32_t i = 0; i < N; i++) {
    HRT_GET_TIMESTAMP(start);
    qp->Read(wr_id, (uint64_t)mr->addr, mr->lkey, len, params.remote,
             params.rkey, true);

    while (qp->poll_recv_cq(&wc) <= 0) {
    }
    HRT_GET_TIMESTAMP(finish);
    HRT_GET_ELAPSED_TICKS(start, finish, &latency);
    measurements.push_back(latency);
    qp->post_recv(mr2, 1);

    while (qp->poll_send_cq(&wc) <= 0) {
    }
  }
  info(log_fp, " \n Read %u bytes\n ", len);
  for (uint32_t i = 0; i < N; i++) {
    double time = HRT_GET_USEC(measurements[i]);
    info(log_fp, " %lf  ", time);
  }
  info(log_fp, "\n ");
  measurements.clear();
}

void measure_write(uint32_t len, uint32_t N) {
  HRT_GET_TIMESTAMP(start);
  for (uint32_t i = 0; i < N; i++) {
    HRT_GET_TIMESTAMP(start);
    qp->Write(wr_id, (uint64_t)mr->addr, mr->lkey, len, params.remote,
              params.rkey, true);

    while (qp->poll_recv_cq(&wc) <= 0) {
    }
    HRT_GET_TIMESTAMP(finish);
    HRT_GET_ELAPSED_TICKS(start, finish, &latency);
    measurements.push_back(latency);
    qp->post_recv(mr2, 1);

    while (qp->poll_send_cq(&wc) <= 0) {
    }
  }
  info(log_fp, " \n Write %u bytes\n ", len);
  for (uint32_t i = 0; i < N; i++) {
    double time = HRT_GET_USEC(measurements[i]);
    info(log_fp, " %lf  ", time);
  }
  info(log_fp, "\n ");
  measurements.clear();
}

void measure_memory_protected_read(uint32_t len, uint32_t N) {
  HRT_GET_TIMESTAMP(start);
  for (uint32_t i = 0; i < N; i++) {
    HRT_GET_TIMESTAMP(start);
    qp->Read(wr_id, (uint64_t)mr->addr, mr->lkey, len, params.remote,
             params.rkey, true, &remregion);

    while (qp->poll_recv_cq(&wc) <= 0) {
    }
    HRT_GET_TIMESTAMP(finish);
    HRT_GET_ELAPSED_TICKS(start, finish, &latency);
    measurements.push_back(latency);
    qp->post_recv(mr2, 1);

    while (qp->poll_send_cq(&wc) <= 0) {
    }
  }
  info(log_fp, " \n Read %u bytes\n ", len);
  for (uint32_t i = 0; i < N; i++) {
    double time = HRT_GET_USEC(measurements[i]);
    info(log_fp, " %lf  ", time);
  }
  info(log_fp, "\n ");
  measurements.clear();
}

void measure_memory_protected_write(uint32_t len, uint32_t N) {
  HRT_GET_TIMESTAMP(start);
  for (uint32_t i = 0; i < N; i++) {
    HRT_GET_TIMESTAMP(start);
    qp->Write(wr_id, (uint64_t)mr->addr, mr->lkey, len, params.remote,
              params.rkey, true, &remregion);

    while (qp->poll_recv_cq(&wc) <= 0) {
    }
    HRT_GET_TIMESTAMP(finish);
    HRT_GET_ELAPSED_TICKS(start, finish, &latency);
    measurements.push_back(latency);
    qp->post_recv(mr2, 1);

    while (qp->poll_send_cq(&wc) <= 0) {
    }
  }
  info(log_fp, " \n Write %u bytes\n ", len);
  for (uint32_t i = 0; i < N; i++) {
    double time = HRT_GET_USEC(measurements[i]);
    info(log_fp, " %lf  ", time);
  }
  info(log_fp, "\n ");
  measurements.clear();
}

int main(int argc, char *argv[]) {
  auto allparams = parse(argc, argv);

  uint32_t sendpsn = allparams["psn"].as<uint32_t>();
  bool drkey = allparams["drkey"].as<bool>();
  enum ibv_qp_crypto crypto =
      (enum ibv_qp_crypto)(allparams["crypto"].as<uint32_t>());
  bool withmemkey = allparams["memkey"].as<bool>();

  uint64_t len = allparams["len"].as<uint64_t>();
  uint64_t N = allparams["num"].as<uint64_t>();

  HRT_INIT(g_timerfreq);
  if (allparams.count("output")) {
    log_fp = fopen(allparams["output"].as<std::string>().c_str(), "w");
  } else {
    log_fp = stdout;
  }

  std::string remote_host =
      allparams["another"].as<std::string>();  // "192.168.1.20"; .c_str()
  std::string my_nick_address =
      allparams["smartnic"].as<std::string>();  //"192.168.1.30";

  RDMA_COM *dma_host = new RDMA_COM(0,   // inline size of QP
                                    10,  // send_size
                                    10,  // recv_size
                                    0,   // we don't init reads
                                    10,  // but we  target for 20 reads
                                    8888, my_nick_address.c_str());

  text(log_fp, " DMA connection is established\n");

  qp = new SequreQP(dma_host->get_connection(2), drkey ? pdkey : NULL,
                    withmemkey ? mymemkey : NULL);

  uint32_t my_qp_num = qp->GetQPN();

  std::this_thread::sleep_for(std::chrono::seconds(1));

  params = {0, 0, 0, sendpsn, my_qp_num};

  params = client_exchange(remote_host.c_str(), 18000, &params);

  printf(" Received params %lu %u  %u %u %u\n", params.remote, params.rkey,
         params.length, params.psn, params.qpn);

  uint32_t remotepsn = params.psn;
  uint32_t dest_qp_num = params.qpn;

  if (drkey) {
    qp->modify_to_RTR(remotepsn, dest_qp_num, crypto);
  } else {
    qp->modify_to_RTR(remotepsn, dest_qp_num, crypto, key, sizeof(key));
  }

  text(log_fp, "[CLIENT] sequre QP ready to receive\n");

  std::this_thread::sleep_for(std::chrono::seconds(1));

  qp->modify_to_RTS(sendpsn);

  text(log_fp, "[CLIENT] sequre QP ready to send\n");

  std::this_thread::sleep_for(std::chrono::seconds(1));

  mr = qp->reg_mem(4096);

  mr2 = qp->reg_mem(4096);
  qp->post_recv(mr2, 1);

  if (!withmemkey) {
    if (len == 0) {
      // do all sizes tests
      for (uint32_t len = 16; len <= 4096; len *= 2) {
        measure_write(len, N);
        measure_read(len, N);
      }

      for (uint32_t len = 4096; len >= 16; len /= 2) {
        measure_write(len, N);
        measure_read(len, N);
      }

    } else {
      measure_write(len, N);
      measure_read(len, N);
    }
  }

  if (withmemkey) {
    text(log_fp, "With memory protection \n");
    remregion = {params.reg_begin, params.reg_length};
    memcpy(remregion.memkey, params.memkey, KDFKEYSIZE);

    if (len == 0) {
      // do all sizes tests
      for (uint32_t len = 16; len <= 4096; len *= 2) {
        measure_memory_protected_write(len, N);
        measure_memory_protected_read(len, N);
      }

      for (uint32_t len = 4096; len >= 16; len /= 2) {
        measure_memory_protected_write(len, N);
        measure_memory_protected_read(len, N);
      }

    } else {
      measure_memory_protected_write(len, N);
      measure_memory_protected_read(len, N);
    }
  }

  delete qp;

  fclose(log_fp);
  return 0;
}
