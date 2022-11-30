#include <chrono>  // std::chrono::seconds
#include <thread>  // std::this_thread::sleep_for
#include "utilities/cxxopts.hpp"
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

cxxopts::ParseResult parse(int argc, char *argv[]) {
  cxxopts::Options options(argv[0], "Simple Secure QP client");
  options.positional_help("[optional args]").show_positional_help();

  try {
    std::stringstream stream;
    stream << "0x" << std::hex << IBV_HDR_HMAC_SHA2_256;
    std::string resultstr(stream.str());

    options.add_options()
        ("server", "server", cxxopts::value<bool>()->default_value("false"))
        ("smartnic", "smartnic address", cxxopts::value<std::string>(), "IP")
        ("another", "Another address", cxxopts::value<std::string>(), "IP")
        ("drkey", "Use key derivation", cxxopts::value<bool>()->default_value("false"))
        ("psn", "Local send psn",cxxopts::value<uint32_t>()->default_value("123"),"N")
        ("crypto", "Protection algorithm", cxxopts::value<uint32_t>()->default_value(resultstr),"N")
        ("memkey", "Use key derivation for memory sub delegation",cxxopts::value<bool>()->default_value("false"))
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

  uint32_t sendpsn = allparams["psn"].as<uint32_t>();
  bool drkey = allparams["drkey"].as<bool>();
  enum ibv_qp_crypto crypto =
      (enum ibv_qp_crypto)(allparams["crypto"].as<uint32_t>());
  bool withmemkey = allparams["memkey"].as<bool>();
  bool server = allparams["server"].as<bool>();

  if (allparams.count("output")) {
    log_fp = fopen(allparams["output"].as<std::string>().c_str(), "w");
  } else {
    log_fp = stdout;
  }

  std::string remote_host =
      allparams["another"].as<std::string>();  // "192.168.1.20"; .c_str()
  std::string my_nick_address =
      allparams["smartnic"].as<std::string>();  //"192.168.1.30";

  // it is a simple send client.

  RDMA_COM *dma_host = new RDMA_COM(0,   // inline size of QP
                                    10,  // send_size
                                    10,  // recv_size
                                    0,   // we don't init reads
                                    10,  // but we  target for 20 reads
                                    8888, my_nick_address.c_str());

  text(log_fp, " DMA connection is established\n");

  SequreQP *qp = new SequreQP(dma_host->get_connection(2), drkey ? pdkey : NULL,
                              withmemkey ? mymemkey : NULL);

  struct ibv_mr *recv_buf = qp->reg_mem(4096, withmemkey);
  qp->post_recv(recv_buf, 1);

  uint32_t my_qp_num = qp->GetQPN();

  exchange_params params = {(uint64_t)recv_buf->addr, recv_buf->rkey,
                            (uint32_t)recv_buf->length, sendpsn, my_qp_num};

  if (withmemkey) {
    // set original region
    ibv_kdf_ctx memkdf =
        initkdf(ibv_kdf_type::KDF_CMAC_AES_128, NULL, KDFKEYSIZE);

    params.reg_length = (uint32_t)recv_buf->length;
    params.reg_begin = (uint64_t)recv_buf->addr;

    memcpy(params.memkey, mymemkey, KDFKEYSIZE);
    subregion_t subreg =
        grant_subregion((uint64_t)recv_buf->addr, 0, 1024,
                        (uint32_t)recv_buf->length, params.memkey, memkdf);

    // set subregion we grant access to
    params.remote = subreg.begin;
    params.length = subreg.length;
    text(log_fp, " we generated memkey: \n");
    printBytes(params.memkey, KDFKEYSIZE);
  }

  text(log_fp, " Send memory region info  %lu %u  %u %u %u\n", params.remote,
       params.rkey, params.length, params.psn, params.qpn);

  if (server) {
    params = server_exchange(18000, &params);
  } else {
    params = client_exchange(remote_host.c_str(), 18000, &params);
  }

  printf(" Received params %lu %u  %u %u %u\n", params.remote, params.rkey,
         params.length, params.psn, params.qpn);

  uint32_t remotepsn = params.psn;
  uint32_t dest_qp_num = params.qpn;

  if (drkey) {
    qp->modify_to_RTR(remotepsn, dest_qp_num, crypto);
  } else {
    qp->modify_to_RTR(remotepsn, dest_qp_num, crypto, key, sizeof(key));
  }

  info(log_fp, "[CLIENT] sequre QP ready to receive\n");

  qp->modify_to_RTS(sendpsn);

  info(log_fp, "[CLIENT] sequre QP ready to send\n");

  if (server) {
    while (1) {
    }
    return 0;
  }

  region_t remregion;
  if (withmemkey) {
    remregion = {params.reg_begin, params.reg_length};
    memcpy(remregion.memkey, params.memkey, KDFKEYSIZE);
  }

  std::this_thread::sleep_for(std::chrono::seconds(1));
  info(log_fp, "[CLIENT] sequre QP ready to send\n");

  struct ibv_mr *mr = qp->reg_mem(1024);
  uint32_t wr_id = 10;

  struct ibv_wc wc;

  bool signalled = true;

  qp->Write(wr_id, (uint64_t)mr->addr, mr->lkey, mr->length, params.remote,
            params.rkey, signalled);

  while (qp->poll_send_cq(&wc) <= 0) {
    // check that request is sent
  }

  while (qp->poll_recv_cq(&wc) <= 0) {
    // check that response received
  }

  info(log_fp, "[CLIENT] Get completion\n");
  assert(wc.opcode == IBV_WC_SECURE_WRITE);
  assert((uint32_t)wc.wr_id == wr_id);

  qp->post_recv(recv_buf, 1);

  qp->Write(wr_id, (uint64_t)mr->addr, mr->lkey, mr->length, params.remote,
            params.rkey, signalled);

  while (qp->poll_send_cq(&wc) <= 0) {
    // check that request is sent
  }

  while (qp->poll_recv_cq(&wc) <= 0) {
    // check that response received
  }

  info(log_fp, "[CLIENT] Get completion\n");
  assert(wc.opcode == IBV_WC_SECURE_WRITE);
  assert((uint32_t)wc.wr_id == wr_id);

  qp->post_recv(recv_buf, 1);

  qp->Read(wr_id, (uint64_t)mr->addr, mr->lkey, mr->length, params.remote,
           params.rkey, signalled);

  while (qp->poll_send_cq(&wc) <= 0) {
  }

  while (qp->poll_recv_cq(&wc) <= 0) {
  }

  info(log_fp, "[CLIENT] Get completion\n");
  assert(wc.opcode == IBV_WC_SECURE_READ);
  assert((uint32_t)wc.wr_id == wr_id);

  qp->post_recv(recv_buf, 1);

  if (withmemkey) {
    qp->Write(wr_id, (uint64_t)mr->addr, mr->lkey, mr->length, params.remote,
              params.rkey, signalled, &remregion);

    while (qp->poll_send_cq(&wc) <= 0) {
      // check that request is sent
    }

    while (qp->poll_recv_cq(&wc) <= 0) {
      // check that response received
    }

    info(log_fp, "[CLIENT] Get completion\n");
    assert(wc.opcode == IBV_WC_SECURE_WRITE);
    assert((uint32_t)wc.wr_id == wr_id);

    qp->post_recv(recv_buf, 1);

    qp->Read(wr_id, (uint64_t)mr->addr, mr->lkey, mr->length, params.remote,
             params.rkey, signalled, &remregion);

    while (qp->poll_send_cq(&wc) <= 0) {
    }

    while (qp->poll_recv_cq(&wc) <= 0) {
    }

    info(log_fp, "[CLIENT] Get completion\n");
    assert(wc.opcode == IBV_WC_SECURE_READ);
    assert((uint32_t)wc.wr_id == wr_id);

    qp->post_recv(recv_buf, 1);
  }

  fclose(log_fp);
  return 0;
}
