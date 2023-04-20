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

#include "rdma_com/rdma_com.hpp"
#include "thread/thread.hpp"

#include "worker/common.hpp"
#include "worker/nic_driver.hpp"

#include "utilities/cxxopts.hpp"

FILE *log_fp;

uint32_t dma_port = 8888;
uint32_t client_port = 9999;

cxxopts::ParseResult parse(int argc, char *argv[]) {
  cxxopts::Options options(argv[0], "Secure smartnic");
  options.positional_help("[optional args]").show_positional_help();

  try {
    options.add_options()
        ("anothernic", "Another nic address", cxxopts::value<std::string>(), "IP")
        ("threads", "number of threads and QP workers", cxxopts::value<uint32_t>()->default_value("1"),"N")
        ("inline", "inline size in  bytes", cxxopts::value<uint32_t>()->default_value("0"), "N")
        ("dmass", "DMA send size in WQEs", cxxopts::value<uint32_t>()->default_value("160"), "N")
        ("dmars", "DMA receive size in WQEs", cxxopts::value<uint32_t>()->default_value("160"), "N")
        ("css", "client send size in WQEs", cxxopts::value<uint32_t>()->default_value("160"), "N")
        ("crs", "client receive size in WQEs", cxxopts::value<uint32_t>()->default_value("320"), "N")
        ("p,packetsize", "packetsize in bytes", cxxopts::value<uint32_t>()->default_value("2048"), "N")
        ("o,output", "Output file", cxxopts::value<std::string>(), "FILE")
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

int main(int argc, char *argv[]) {
  auto allparams = parse(argc, argv);

  if (allparams.count("output")) {
    log_fp = fopen(allparams["output"].as<std::string>().c_str(), "w");
  } else {
    log_fp = stdout;
  }

  uint32_t numthreads = allparams["threads"].as<uint32_t>();
  uint32_t inlinesize = allparams["inline"].as<uint32_t>();

  uint32_t dmass = allparams["dmass"].as<uint32_t>();
  uint32_t dmars = allparams["dmars"].as<uint32_t>();
  uint32_t css = allparams["css"].as<uint32_t>();
  uint32_t crs = allparams["crs"].as<uint32_t>();

  uint32_t packetsize = allparams["packetsize"].as<uint32_t>();

  std::string anothernicstr = "";
  bool server = true;
  if (allparams.count("anothernic")) {
    server = false;
    anothernicstr = allparams["anothernic"].as<std::string>();
  }

  RDMA_COM *comnic =
      new RDMA_COM(inlinesize,  // inline
                   css,         // send_size
                   crs,         // recv_size
                   0,           // no rdma reads
                   0,           // no rdma reads
                   client_port, server ? NULL : anothernicstr.c_str(), false,
                   false, false);  //  server // with_shared_queue

  std::vector<Connection *> all_nic_connections;

  for (uint32_t workerid = 0; workerid < numthreads;) {
    Connection *tempcon = NULL;
    if (server) {
      tempcon = comnic->accept_connection(1, false);
    } else {
      tempcon = comnic->get_connection(1);
    }
    if (tempcon != NULL) {
      all_nic_connections.push_back(tempcon);
      workerid++;
    } else {
      //          text(log_fp,"Error for nic connection: %u \n",workerid);
    }
  }
  text(log_fp, "[NIC] All  smartnic connections are installed\n");

  /*
      communications between NIC and a HOST

  */

  RDMA_COM *dma = new RDMA_COM(inlinesize,  // inline
                               dmass,       // send_size
                               dmars,       // recv_size
                               10,          // we init 10 reads
                               0,           // no target
                               dma_port, NULL, false, false, false);  //  server

  std::vector<Connection *> all_dma_connections;
  // dma->create_shared();
  for (uint32_t workerid = 0; workerid < numthreads;) {
    Connection *tempcon = dma->accept_connection(1, false);
    if (tempcon != NULL) {
      all_dma_connections.push_back(tempcon);
      workerid++;
    } else {
      //          text(log_fp,"Error for dma: %u \n",workerid);
    }
  }

  text(log_fp, "[NIC] All  DMA connections are installed\n");

  LauncherMaster *m = new LauncherMaster();

  for (uint32_t workerid = 0; workerid < numthreads; workerid++) {
    Thread *t = new Thread(workerid);

    SecureWorker *secw =
        new SecureWorker(workerid, t, all_nic_connections[workerid],
                         all_dma_connections[workerid], packetsize);

    t->install_worker(secw);
    m->add_thread(t);
  }
//test
  m->launch();

  delete m;
  // delete dma;
  // delete com;
  fclose(log_fp);
  return 0;
}
