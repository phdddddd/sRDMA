#include "worker/client_bw.hpp"
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

FILE *log_fp;

unsigned long long g_timerfreq;

cxxopts::ParseResult parse(int argc, char *argv[]) {
  cxxopts::Options options(argv[0],
                           "Secure QP bandwidth test with multiple workers");
  options.positional_help("[optional args]").show_positional_help();

  try {
    std::stringstream stream;
    stream << "0x" << std::hex << IBV_HDR_HMAC_SHA2_256;
    std::string resultstr(stream.str());

    options.add_options()
    ("smartnic", "smartnic address", cxxopts::value<std::string>(), "IP")
    ("another", "Another address", cxxopts::value<std::string>(), "IP")
    ("drkey", "Use key derivation", cxxopts::value<bool>()->default_value("false"))
    ("psn", "Local send psn", cxxopts::value<uint32_t>()->default_value("123"),"N")
    ("crypto", "Protection algorithm",cxxopts::value<uint32_t>()->default_value(resultstr),"N")
    ("memkey", "Use key derivation for memory sub delegation",cxxopts::value<bool>()->default_value("false"))
    ("len", "payload size",cxxopts::value<uint64_t>()->default_value(std::to_string(2048)), "N")
    ("num", "Number of measurements, 0 - for unlimited",cxxopts::value<uint64_t>()->default_value(std::to_string(100)),"N")
    ("threads", "Total number of QP created",cxxopts::value<uint32_t>()->default_value(std::to_string(1)), "N")
    ("workers", "Total number of smartnic workers",cxxopts::value<uint32_t>()->default_value(std::to_string(1)), "N")
    ("batch", "batch",cxxopts::value<uint32_t>()->default_value(std::to_string(32)),"N")
    ("each", "each in seconds",cxxopts::value<float>()->default_value(std::to_string(0.1)), "N")
    ("outstand", "Number of outstanding requests",cxxopts::value<uint32_t>()->default_value(std::to_string(96)), "N")
    ("sendsize", "sendsize in WQEs",cxxopts::value<uint32_t>()->default_value(std::to_string(128)),"N")
    ("recvsize", "recvsize in WQEs",cxxopts::value<uint32_t>()->default_value(std::to_string(128)),"N")
    ("test", "1-write, 2-read",cxxopts::value<uint32_t>()->default_value(std::to_string(1)),"N")
    ("o,output", "Output file", cxxopts::value<std::string>(),"FILE")
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

  HRT_INIT(g_timerfreq);
  if (allparams.count("output")) {
    log_fp = fopen(allparams["output"].as<std::string>().c_str(), "w");
  } else {
    log_fp = stdout;
  }

  uint32_t sendpsn = allparams["psn"].as<uint32_t>();
  bool drkey = allparams["drkey"].as<bool>();
  enum ibv_qp_crypto crypto =
      (enum ibv_qp_crypto)(allparams["crypto"].as<uint32_t>());
  bool withmemkey = allparams["memkey"].as<bool>();

  uint64_t len = allparams["len"].as<uint64_t>();
  uint64_t N = allparams["num"].as<uint64_t>();
  uint32_t batch = allparams["batch"].as<uint32_t>();
  uint32_t maxoutstand = allparams["outstand"].as<uint32_t>();
  float cb_timeout = allparams["each"].as<float>();

  uint32_t numthreads = allparams["threads"].as<uint32_t>();
  uint32_t total_smartnic_workers = allparams["workers"].as<uint32_t>();
  uint32_t test = allparams["test"].as<uint32_t>();

  uint32_t send_size = allparams["sendsize"].as<uint32_t>();
  uint32_t recv_size = allparams["recvsize"].as<uint32_t>();

  std::string remote_host =
      allparams["another"].as<std::string>();  // "192.168.1.20"; .c_str()
  std::string my_nick_address =
      allparams["smartnic"].as<std::string>();  //"192.168.1.30";

  LauncherMaster *m = new LauncherMaster();

  std::vector<AggregateWorker *> workers;

  if (numthreads > 4) {
    for (uint32_t threadid = 0; threadid < 4; threadid++) {
      Thread *t = new Thread(threadid, cb_timeout);
      workers.push_back(new AggregateWorker());
      t->install_worker(workers[threadid]);
      m->add_thread(t);
    }
  }

  RDMA_COM *dma_host = new RDMA_COM(0,          // inline size of QP
                                    send_size,  // send_size
                                    recv_size,  // recv_size
                                    0,          // we don't init reads
                                    10,         // but we  target for 20 reads
                                    8888, my_nick_address.c_str());

  text(log_fp, " DMA connection is established\n");

  std::vector<Connection *> all_dma_connections;
  for (uint32_t threadid = 0; threadid < numthreads; threadid++) {
    all_dma_connections.push_back(dma_host->get_connection(2));
  }

  for (uint32_t threadid = 0; threadid < numthreads; threadid++) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    uint32_t workerid = threadid % total_smartnic_workers;  // todo port shift

    SequreQP *qp =
        new SequreQP(all_dma_connections[threadid], drkey ? pdkey : NULL,
                     withmemkey ? mymemkey : NULL, 4096 * 10);
    uint32_t my_qp_num = qp->GetQPN();

    std::this_thread::sleep_for(std::chrono::seconds(1));
    exchange_params params = {0, 0, 0, sendpsn, my_qp_num};

    params = client_exchange(remote_host.c_str(), 18000 + workerid, &params);
    text(log_fp, "[QP(%u)] Received params %lu %u \n", threadid, params.remote,
         params.rkey);

    uint32_t remotepsn = params.psn;
    uint32_t dest_qp_num = params.qpn;

    if (drkey) {
      qp->modify_to_RTR(remotepsn, dest_qp_num, crypto);
    } else {
      qp->modify_to_RTR(remotepsn, dest_qp_num, crypto, key, sizeof(key));
    }

    text(log_fp, "[CLIENT] sequre QP ready to receive\n");

 
    qp->modify_to_RTS(sendpsn);

    text(log_fp, "[CLIENT] sequre QP ready to send\n");

    std::this_thread::sleep_for(std::chrono::seconds(1));

    region_t remregion = {0, 0};

    if (withmemkey) {
      text(log_fp, "With memory protection \n");
      remregion = {params.reg_begin, params.reg_length};
      memcpy(remregion.memkey, params.memkey, KDFKEYSIZE);
      printBytes(remregion.memkey, KDFKEYSIZE);
    }

    if (numthreads <= 4) {
      Thread *t = new Thread(threadid, cb_timeout);
      t->install_worker(new ClientBandwidthWorker(
          threadid, test, qp, params.remote, params.rkey, N, maxoutstand, batch,
          len, recv_size, send_size, remregion));
      m->add_thread(t);
    } else {
      uint32_t attach_to_worker = threadid % 4;
      workers[attach_to_worker]->AddWorker(new ClientBandwidthWorker(
          threadid, test, qp, params.remote, params.rkey, N, maxoutstand, batch,
          len, recv_size, send_size, remregion));
    }
  }

  std::this_thread::sleep_for(std::chrono::seconds(1));
  text(log_fp, "[CLIENT] Start benchamrk\n");

  m->launch();

  delete m;
  fclose(log_fp);
  return 0;
}
