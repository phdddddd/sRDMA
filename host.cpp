#include <stdlib.h>
#include <cassert>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>  // std::cout
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include "utilities/cxxopts.hpp"

#include "worker/TCPExchange.hpp"
#include "worker/secure_qp.hpp"

FILE *log_fp;

unsigned char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,  // 16
                       0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};  // 32

unsigned char pdkey[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};  // 16

unsigned char mymemkey[] = {0x1e, 0x1e, 0x15, 0x16, 0x28, 0x7e,
                            0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                            0x09, 0xcf, 0x4f, 0x3c};  // 16

cxxopts::ParseResult parse(int argc, char *argv[]) {
  cxxopts::Options options(argv[0], "Secure QP host");
  options.positional_help("[optional args]").show_positional_help();

  try {
    std::stringstream stream;
    stream << "0x" << std::hex << IBV_HDR_HMAC_SHA2_256;
    std::string resultstr(stream.str());

    options.add_options()
        ("smartnic", "smartnic address",cxxopts::value<std::string>(),"IP")
        ("drkey", "Use key derivation",cxxopts::value<bool>()->default_value("false"))
        ("psn", "Local send psn", cxxopts::value<uint32_t>()->default_value("0"),"N")
        ("crypto", "Protection algorithm",cxxopts::value<uint32_t>()->default_value(resultstr),"N")  // std::to_string(IBV_HDR_HMAC_SHA2_256)
        ("threads", "Total number of QP created",cxxopts::value<uint32_t>()->default_value(std::to_string(1)), "N")
        ("workers", "Total number of smartnic workers",cxxopts::value<uint32_t>()->default_value(std::to_string(1)), "N")
        ("size", "Buffer size per thread",cxxopts::value<uint32_t>()->default_value(std::to_string(4096)),"N")
        ("memkey", "Use key derivation for memory sub delegation",cxxopts::value<bool>()->default_value("false"))
        ("o,output", "Output file", cxxopts::value<std::string>(), "FILE")
        ("help", "Print help");

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    if (!result.count("smartnic")) {
      throw new cxxopts::OptionException("Must specify smartnic ip address");
    }

    return result;

  } catch (const cxxopts::OptionException &e) {
    std::cout << "error parsing options: " << e.what() << std::endl;
    std::cout << options.help({""}) << std::endl;
    exit(1);
  }
}

int main(int argc, char *argv[]) {
  auto allparams = parse(argc, argv);

  if (allparams.count("output")) {
    log_fp = fopen(allparams["output"].as<std::string>().c_str(), "w");
  } else {
    log_fp = stdout;
  }

  uint32_t sendpsn = allparams["psn"].as<uint32_t>();
  bool drkey = allparams["drkey"].as<bool>();
  enum ibv_qp_crypto crypto =
      (enum ibv_qp_crypto)(allparams["crypto"].as<uint32_t>());
  uint32_t numthreads = allparams["threads"].as<uint32_t>();
  bool withmemkey = allparams["memkey"].as<bool>();

  uint32_t total_smartnic_workers = allparams["workers"].as<uint32_t>();

  uint32_t size = allparams["size"].as<uint32_t>();


  std::string my_nick_address =
      allparams["smartnic"].as<std::string>();  //"192.168.1.30";

  ibv_kdf_ctx memkdf = NULL;
  if (withmemkey) {
    memkdf = initkdf(ibv_kdf_type::KDF_CMAC_AES_128, NULL, KDFKEYSIZE);
  }

  /*
      communications between host and the nic

  */
  RDMA_COM *dma_host = new RDMA_COM(0,   // inline size of QP
                                    2,   // send_size
                                    2,   // recv_size
                                    0,   // we don't init reads
                                    20,  // but we  target for 20 reads
                                    8888, my_nick_address.c_str());

  text(log_fp, " DMA connection is established\n");

  std::vector<Connection *> all_dma_connections;
  for (uint32_t threadid = 0; threadid < numthreads; threadid++) {
    all_dma_connections.push_back(dma_host->get_connection(1));
  }

  for (uint32_t threadid = 0; threadid < numthreads; threadid++) {
    text(log_fp, " Create DMA connection \n");

    uint32_t workerid = threadid % total_smartnic_workers;

    SequreQP *qp =
        new SequreQP(all_dma_connections[threadid], drkey ? pdkey : NULL,
                     withmemkey ? mymemkey : NULL);

    char *buf = (char *)aligned_alloc(4096, size);
    struct ibv_mr *mr = qp->reg_mem(buf, size, withmemkey);

    uint32_t my_qp_num = qp->GetQPN();

    exchange_params params = {(uint64_t)mr->addr, mr->rkey,
                              (uint32_t)mr->length, sendpsn, my_qp_num};

    if (withmemkey) {
      // set original region
      params.reg_length = (uint32_t)mr->length;
      params.reg_begin = (uint64_t)mr->addr;

      memcpy(params.memkey, mymemkey, KDFKEYSIZE);
      //question:为什么要这么操作，有什么意义
      subregion_t subreg =
          grant_subregion((uint64_t)mr->addr, 0, size, (uint32_t)mr->length,
                          params.memkey, memkdf);

      // set subregion we grant access to
      params.remote = subreg.begin;
      params.length = subreg.length;
      text(log_fp, " we generated memkey: \n");
      printBytes(params.memkey, KDFKEYSIZE);
    }

    text(log_fp, " Send memory region info  %lu %u  %u %u %u\n", params.remote,
         params.rkey, params.length, params.psn, params.qpn);
//question:为什么这里用tcp进行参数交换
    params = server_exchange(18000 + workerid, &params);

    text(log_fp, " Received params %lu %u  %u %u %u\n", params.remote,
         params.rkey, params.length, params.psn, params.qpn);

    uint32_t remotepsn = params.psn;
    uint32_t dest_qp_num = params.qpn;

    if (drkey) {
      qp->modify_to_RTR(remotepsn, dest_qp_num, crypto);
    } else {
      qp->modify_to_RTR(remotepsn, dest_qp_num, crypto, key, sizeof(key));
    }
 
    qp->modify_to_RTS(sendpsn);
  }

  while (1) {
  }
  fclose(log_fp);
  return 0;
}
