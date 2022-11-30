#include "utilities/cxxopts.hpp"

#include <fstream>
#include <iostream>
#include "worker/tracer.hpp"

cxxopts::ParseResult parse(int argc, char *argv[]) {
  cxxopts::Options options(argv[0], "Trace parser");

  options.positional_help("[optional args]").show_positional_help();

  try {
    std::stringstream stream;
    stream << "0x" << std::hex << IBV_HDR_HMAC_SHA2_256;
    std::string resultstr(stream.str());

    options.add_options()(
        "p,payload", "Payload size in bytes",
        cxxopts::value<uint32_t>()->default_value(std::to_string(2048)),
        "N")("i,input", "Input", cxxopts::value<std::string>())(
        "o,output", "Output file", cxxopts::value<std::string>())("help",
                                                                  "Print help");

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
      std::cout << options.help({""}) << std::endl;
      exit(0);
    }

    if (!result.count("input")) {
      throw cxxopts::OptionException("input must be specified");
    }

    return result;

  } catch (const cxxopts::OptionException &e) {
    std::cout << "error parsing options: " << e.what() << std::endl;
    std::cout << options.help({""}) << std::endl;
    exit(1);
  }
}

std::vector<std::string> split(const std::string &s, char delimiter) {
  std::vector<std::string> tokens;
  std::string token;
  std::istringstream tokenStream(s);
  while (std::getline(tokenStream, token, delimiter)) {
    tokens.push_back(token);
  }
  return tokens;
}

FILE *log_fp;

int main(int argc, char *argv[]) {
  log_fp = stdout;
  auto allparams = parse(argc, argv);

  std::string input = allparams["input"].as<std::string>();
  uint32_t payload = allparams["payload"].as<uint32_t>();

  std::string output;
  if (allparams.count("output")) {
    output = allparams["output"].as<std::string>();
  } else {
    std::size_t pos = input.find(".");
    output = input.substr(0, pos) + "_" + std::to_string(payload) + ".bin";
  }
  std::ifstream infile(input);

  uint32_t entries = 0;
  uint32_t reads = 0;
  uint32_t writes = 0;
  uint64_t readbytes = 0;
  uint64_t writebytes = 0;

  uint32_t readpackets = 0;
  uint32_t writepackets = 0;

  if (infile.is_open()) {
    std::ofstream outfile(output, std::ofstream::binary);

    std::string line;
    while (std::getline(infile, line)) {
      entries++;

      std::vector<std::string> elements = split(line, ',');
      if (elements.size() < 4) {
        continue;
      }
      uint32_t size = stoul(elements[2]);
      uint32_t op =
          (elements[3].compare("r") == 0 || elements[3].compare("R") == 0)
              ? READ_OP
              : WRITE_OP;
      // printf("op: %u %u\n", op, size);
      if (op == READ_OP) {
        reads++;
        readbytes += size;
        readpackets += size / payload + (size % payload != 0);
      } else {
        writes++;
        writebytes += size;
        writepackets += size / payload + (size % payload != 0);
      }

      request_t req;
      req.type = op;
      while (size > 0) {
        req.len = std::min(payload, size);
        outfile.write((char *)&req, sizeof(req));
        size -= req.len;
      }
    }

    infile.close();
    outfile.close();
  } else {
    printf("Error input file\n");
    return 1;
  }

  printf("Output written to %s \n", output.c_str());
  printf(
      "Statistics:\n Reads: %u ReadBytes  %lu ReadPackets:  %u\nWrites: %u "
      "WriteBytes %lu WritePackets: %u\n",
      reads, readbytes, readpackets, writes, writebytes, writepackets);

  return 0;
}
