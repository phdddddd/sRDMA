#include "utilities/cxxopts.hpp"
#include <fstream>
#include <iostream>
#include "worker/tracer.hpp"

cxxopts::ParseResult parse(int argc, char *argv[]) {
  cxxopts::Options options(argv[0], "Trace generator of YCSB like workload");

  options.positional_help("[optional args]").show_positional_help();

  try {
    std::stringstream stream;
    stream << "0x" << std::hex << IBV_HDR_HMAC_SHA2_256;
    std::string resultstr(stream.str());

    options.add_options()
      ("n,entries", "trace length",cxxopts::value<uint64_t>()->default_value("2000000"),"N")
      ("p,payload", "Payload size in bytes",cxxopts::value<uint32_t>()->default_value(std::to_string(2048)),"N")
      ("r,read", "read percentage (0-100)",cxxopts::value<uint32_t>()->default_value("5"),"N")
      ("o,output", "Output file", cxxopts::value<std::string>())
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

int main(int argc, char *argv[]) {
  srand(1);
  log_fp = stdout;
  auto allparams = parse(argc, argv);

  uint64_t N = allparams["entries"].as<uint64_t>();
  uint32_t readp = allparams["read"].as<uint32_t>();
  uint32_t payload = allparams["payload"].as<uint32_t>();

  std::string output;
  if (allparams.count("output")) {
    output = allparams["output"].as<std::string>();
  } else {
    output = "write" + std::to_string(100 - readp) + "_read" +
             std::to_string(readp) + "_" + std::to_string(payload) + ".bin";
  }

  uint32_t reads = 0;
  uint32_t writes = 0;
  uint64_t readbytes = 0;
  uint64_t writebytes = 0;

  std::ofstream outfile(output, std::ofstream::binary);

  for (uint64_t i = 0; i < N; i++) {
    uint32_t rndval = rand() % 100;
    uint32_t op = rndval < readp ? READ_OP : WRITE_OP;

    if (op == READ_OP) {
      reads++;
      readbytes += payload;
    } else {
      writes++;
      writebytes += payload;
    }

    request_t req;
    req.type = op;
    req.len = payload;
    outfile.write((char *)&req, sizeof(req));
  }

  outfile.close();

  printf("Output written to %s \n", output.c_str());
  printf(
      "Statistics:\n Reads: %u ReadBytes  %lu \nWrites: %u WriteBytes %lu \n",
      reads, readbytes, writes, writebytes);

  return 0;
}
