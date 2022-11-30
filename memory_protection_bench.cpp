#include <chrono>  // std::chrono::seconds
#include <thread>  // std::this_thread::sleep_for
#include "security/security.hpp"
#include "utilities/cxxopts.hpp"
#include "utilities/get_clock.h"

unsigned char mymemkey[] = {0x7e, 0x7e, 0x15, 0x16, 0x28, 0x7e,
                            0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                            0x09, 0xcf, 0x4f, 0x3c};  // 16
FILE *log_fp;

std::vector<double> measurements;

cxxopts::ParseResult parse(int argc, char *argv[]) {
  cxxopts::Options options(argv[0], "Secure QP trace test");
  options.positional_help("[optional args]").show_positional_help();

  try {
    options.add_options()
      ("depth", "maximum depth of the tree", cxxopts::value<uint32_t>()->default_value(std::to_string(10)), "N")
      ("num", "Number of measurements",cxxopts::value<uint32_t>()->default_value(std::to_string(10)),"N")
      ("batch", "batch", cxxopts::value<uint32_t>()->default_value(std::to_string(1000)),"N")
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

int main(int argc, char *argv[]) {
  auto allparams = parse(argc, argv);

  int no_cpu_freq_fail = 0;
  double mhz;
  mhz = get_cpu_mhz(no_cpu_freq_fail);
  cycles_t c1, c2;

  if (!mhz) {
    printf("Unable to calibrate cycles. Exiting.\n");
    return 2;
  }

  uint32_t N = allparams["num"].as<uint32_t>();
  uint32_t batch = allparams["batch"].as<uint32_t>();
  uint32_t maxdepth = allparams["depth"].as<uint32_t>();

  if (allparams.count("output")) {
    log_fp = fopen(allparams["output"].as<std::string>().c_str(), "w");
  } else {
    log_fp = stdout;
  }

  ibv_kdf_ctx kdfctx =
      initkdf(ibv_kdf_type::KDF_CMAC_AES_128, mymemkey, KDFKEYSIZE);
  unsigned char *derivedkey = (unsigned char *)malloc(KDFKEYSIZE);
  memcpy(derivedkey, mymemkey, KDFKEYSIZE);

  uint64_t regionstart = 0;
  uint32_t offset = 0;
  uint32_t length = 2;

  // warmup
  for (uint32_t j = 0; j < 1000000; j++) {
    volatile int ret = calculate_memory_MAC(regionstart, offset, length, 2,
                                            derivedkey, kdfctx);
    assert(ret == 0);
  }

  for (int d = 0; d < maxdepth; d++) {
    uint32_t region_size = (2 << d);

    for (uint32_t i = 0; i < N; i++) {
      c1 = get_cycles();

      for (uint32_t j = 0; j < batch; j++) {
        volatile int ret = calculate_memory_MAC(
            regionstart, offset, length, region_size, derivedkey, kdfctx);
        if (ret != d) {
          printf("Error\n");
          exit(1);
        }
      }
      c2 = get_cycles();

      measurements.push_back((c2 - c1) / mhz);
    }
    info(log_fp, "Depth %d\n ", d);
    for (uint32_t i = 0; i < N; i++) {
      double time = measurements[i];
      info(log_fp, " %lf  ", time);
    }
    info(log_fp, "\n ");
    measurements.clear();
  }

  return 0;
}
