// gcc main.c -lcrypto -lgcrypt -lgpg-error
#include "security/security.hpp"

FILE *log_fp;
int main(int argc, char *argv[]) {
  int ret = 0;
  log_fp = stdout;
  unsigned char key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                         0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                         0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  unsigned char message[] = {
      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
      0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  };

  unsigned char *tempbuf = (unsigned char *)malloc(128);
  unsigned char *header = (unsigned char *)malloc(128);
  // MAC will be read in the header buffer after actual header.
  header[0] = 0x6b;
  header[1] = 0xc1;
  header[2] = 0xbe;
  header[3] = 0xe2;

  nonce_t send = 2;
  nonce_t recv = 2;
  printBytes((unsigned char *)&send, 16);

  ibv_secure_ctx *qpctx;

  qpctx = init(IBV_HDR_CMAC_AES_256, key, send, recv);
  assert(qpctx);

  uint32_t macsize = onsend(qpctx, header, 4, message, sizeof(message));
  printf("%u\n", macsize);
  printBytes(header + 4, macsize);

  bool success = onreceive(qpctx, header, 4, message, sizeof(message), tempbuf);

  printf("%s\n", success ? "success" : "fail ");

  macsize = onsend(qpctx, header, 4, message, sizeof(message));
  printf("%u\n", macsize);
  printBytes(header + 4, macsize);

  success = onreceive(qpctx, header, 4, message, sizeof(message), tempbuf);
  printf("%s\n", success ? "success" : "fail ");

  printf("----- DRKey test \n");

  ibv_kdf_ctx kdfctx = initkdf(ibv_kdf_type::KDF_CMAC_AES_128, key, KDFKEYSIZE);
  qpctx = init(IBV_HDR_CMAC_AES_256, NULL, send, recv);
  assert(qpctx);

  const char *input = "psn 18903";

  unsigned char *derivedkey = (unsigned char *)malloc(KDFKEYSIZE);

  kdf(kdfctx, (unsigned char *)input, 9, derivedkey, KDFKEYSIZE);

  printBytes(derivedkey, KDFKEYSIZE);
  printf("onsend \n");
  macsize = onsend(qpctx, header, 4, message, sizeof(message), derivedkey);
  printf("macsize %u\n", macsize);
  printBytes(header + 4, macsize);

  success = onreceive(qpctx, header, 4, message, sizeof(message), tempbuf,
                      derivedkey);

  printf("%s\n", success ? "success" : "fail ");

  // return 0;

  unsigned char *key2 = (unsigned char *)malloc(KDFKEYSIZE);
  memcpy(key2, key, KDFKEYSIZE);
  region_t origreg = {123, 1024 * 8};
  region_t subreg =
      grant_subregion(origreg.begin, 7023, 30, origreg.length, key2, kdfctx);

  printf("We get %lu %u \n", subreg.begin, subreg.length);

  printf("We access %lu %u \n", subreg.begin + 4, 10);
  calculate_memory_MAC(subreg.begin, 4, 10, subreg.length, key2, kdfctx);
  unsigned char *key3 = (unsigned char *)malloc(KDFKEYSIZE);
  memcpy(key3, key, KDFKEYSIZE);
  printf("We verify %lu %u \n", subreg.begin + 4, 10);
  calculate_memory_MAC(origreg.begin, subreg.begin + 4 - origreg.begin, 10,
                       origreg.length, key3, kdfctx);
  if (memcmp(key3, key2, KDFKEYSIZE) == 0) {
    printf("verified\n");
  } else {
    printf("not verified\n");
  }

  /*
    grant_subregion(123, 100, 100, 1024*8, NULL);
    grant_subregion(123, 0, 255, 1024*8, NULL);
    grant_subregion(123, 0, 256, 1024*8, NULL);
    grant_subregion(123, 0, 257, 1024*8, NULL);
    grant_subregion(123, 4, 1, 1024*8, NULL);
    grant_subregion(123, 7023, 30, 1024*8, NULL);

    calculate_memory_MAC(123, 0, 1024*8, 1024*8, NULL);

    calculate_memory_MAC(123, 1900, 100, 1024*8, NULL);
    calculate_memory_MAC(123+1900, 0, 100, 100, NULL);
    calculate_memory_MAC(123+1900, 0, 100, 100, NULL);
  */
  return ret;
}
