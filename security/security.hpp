#pragma once
#include <assert.h>
#include <inttypes.h>
#include <openssl/cmac.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>
#include "../utilities/debug.h"

typedef unsigned __int128 nonce_t;
typedef unsigned __int128 uint128_t;

#define KDFKEYSIZE 16

void printBytes(unsigned char *buf, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    text(log_fp, "%02x ", buf[i]);
  }
  text(log_fp, "\n");
}

// calcualtes next power of two.
uint32_t next_pow2(uint32_t x) {
  x -= 1;
  x |= (x >> 1);
  x |= (x >> 2);
  x |= (x >> 4);
  x |= (x >> 8);
  x |= (x >> 16);
  return x + 1;
}

struct region_t {
  uint64_t begin;
  uint32_t length;
  unsigned char memkey[KDFKEYSIZE];
};

struct subregion_t {
  uint64_t begin;
  uint32_t length;
};

enum ibv_qp_crypto : uint32_t {
  IBV_NO_SECURITY = 0x0000,
  /*Message authentication codes */
  /* Hash-based MACs*/
  /* Header authentication*/
  IBV_HDR_HMAC_SHA1_160 = 0x1001,  // EVP_sha1()

  IBV_HDR_HMAC_SHA2_224 = 0x1002,  // EVP_sha224
  IBV_HDR_HMAC_SHA2_256 = 0x1003,  // EVP_sha256
  IBV_HDR_HMAC_SHA2_384 = 0x1004,  // EVP_sha384
  IBV_HDR_HMAC_SHA2_512 = 0x1005,  // EVP_sha512

  IBV_HDR_HMAC_SHA3_224 = 0x1006,  // EVP_sha3_224
  IBV_HDR_HMAC_SHA3_256 = 0x1007,  // EVP_sha3_256
  IBV_HDR_HMAC_SHA3_384 = 0x1008,  // EVP_sha3_384
  IBV_HDR_HMAC_SHA3_512 = 0x1009,  // EVP_sha3_512

  /* Packet authentication*/
  IBV_PCKT_HMAC_SHA1_160 = 0x2001,  // EVP_sha1()

  IBV_PCKT_HMAC_SHA2_224 = 0x2002,  // EVP_sha224
  IBV_PCKT_HMAC_SHA2_256 = 0x2003,  // EVP_sha256
  IBV_PCKT_HMAC_SHA2_384 = 0x2004,  // EVP_sha384
  IBV_PCKT_HMAC_SHA2_512 = 0x2005,  // EVP_sha512

  IBV_PCKT_HMAC_SHA3_224 = 0x2006,  // EVP_sha3_224
  IBV_PCKT_HMAC_SHA3_256 = 0x2007,  // EVP_sha3_256
  IBV_PCKT_HMAC_SHA3_384 = 0x2008,  // EVP_sha3_384
  IBV_PCKT_HMAC_SHA3_512 = 0x2009,  // EVP_sha3_512
  /* Cipher-based MACs*/
  /* Header authentication*/
  IBV_HDR_CMAC_AES_96 = 0x3001,  // aes-[128|192|256]-ocb
  IBV_HDR_CMAC_AES_128 = 0x3002,
  IBV_HDR_CMAC_AES_192 = 0x3003,
  IBV_HDR_CMAC_AES_256 = 0x3004,
  IBV_HDR_CMAC_CHACHA20_POLY1305 = 0x3005,  // EVP_chacha20_poly1305
  /* Packet authentication*/
  IBV_PCKT_CMAC_AES_96 = 0x4001,  // aes-[128|192|256]-ocb
  IBV_PCKT_CMAC_AES_128 = 0x4002,
  IBV_PCKT_CMAC_AES_192 = 0x4003,
  IBV_PCKT_CMAC_AES_256 = 0x4004,
  IBV_PCKT_CMAC_CHACHA20_POLY1305 = 0x4005,  // EVP_chacha20_poly1305
  /* Authenticated Encryption*/
  IBV_AEAD_AES_96 = 0x5001,  // aes-[128|192|256]-ocb
  IBV_AEAD_AES_128 = 0x5002,
  IBV_AEAD_AES_192 = 0x5003,
  IBV_AEAD_AES_256 = 0x5004,
  IBV_AEAD_CHACHA20_POLY1305 = 0x5005,  // EVP_chacha20_poly1305

};

#define MAX_KEY_LENGTH 32

struct rts_attribure_t {
  uint32_t mypsn;
};

struct rtr_attribure_t {
  ibv_qp_crypto cryptoname;
  uint32_t remote_psn;
  uint32_t dest_qp_num;
  unsigned char key[MAX_KEY_LENGTH];
};

struct init_attribure_t {
  bool drkey;
  unsigned char pdkey[KDFKEYSIZE];
  bool withmemkey;
  unsigned char memkey[KDFKEYSIZE];
};

struct mem_attribure_t {
  uint64_t begin;
  uint32_t length;
  uint32_t rkey;
};

struct secure_attribure_header_t {
  uint64_t type;
};

#define INIT 1
#define RTS 2
#define RTR 3
#define MEMORY_REG 4

enum class crypto_type_t : uint8_t {
  HMAC = 0,
  CMAC = 1,
  AEDS = 2,
  NOSECURITY = 3,
};

enum class data_t : uint8_t {
  HEADER = 0,
  PACKET = 1,
};

typedef CMAC_CTX *ibv_kdf_ctx;

enum class ibv_kdf_type : uint8_t {
  KDF_CMAC_AES_128 = 0x1,
};

struct ibv_secure_ctx {
  crypto_type_t type;  // 2bits
  data_t dtype;        // 1bits
  uint8_t tagbytes;    // 3bits
  uint8_t key_length;  // 3bits
  void *ctx;           // 48bits
  nonce_t sendnonce;   // 128 bits
  nonce_t recvnonce;   // 128 bits
};

#define CLASSICHMAC

#ifndef CLASSICHMAC
int ctrl_ign_unsupported(EVP_MAC_CTX *ctx, int cmd, ...) {
  va_list args;
  int rv;

  va_start(args, cmd);
  rv = EVP_MAC_vctrl(ctx, cmd, args);
  va_end(args);

  if (rv == -2) {
    rv = 1; /* Ignore unsupported, pretend it worked fine */
  }

  return rv;
}

#endif

ibv_secure_ctx *init(ibv_qp_crypto cryptoname, const unsigned char *key,
                     nonce_t sendnonce, nonce_t recvnonce) {
  text(log_fp, "[SECURITY] : init context \n");
  ibv_secure_ctx *ret = (ibv_secure_ctx *)malloc(sizeof(ibv_secure_ctx));
  bool dummy_key = false;
  ret->sendnonce = sendnonce;
  ret->recvnonce = recvnonce;

  if (cryptoname == IBV_NO_SECURITY) {
    ret->type = crypto_type_t::NOSECURITY;
    ret->tagbytes = 0;
  } else if (cryptoname < IBV_HDR_CMAC_AES_96) {
    text(log_fp, "[SECURITY] : Create HMAC ctx \n");
#ifdef CLASSICHMAC
    HMAC_CTX *hmacctx = HMAC_CTX_new();
#else
    EVP_MAC_CTX *hmacctx = EVP_MAC_CTX_new_id(EVP_MAC_HMAC);
#endif
    if (hmacctx == NULL) {
      text(log_fp, "error HMAC_CTX_new\n");
      goto error;
    }
    ret->ctx = hmacctx;
    ret->type = crypto_type_t::HMAC;

    const EVP_MD *md = NULL;

    switch (cryptoname) {
      case IBV_HDR_HMAC_SHA1_160:
        text(log_fp, "Create IBV_HDR_HMAC_SHA1_160\n");
        md = EVP_sha1();
        ret->key_length = 16;
        ret->tagbytes = 20;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_HMAC_SHA2_224:
        text(log_fp, "Create IBV_HDR_HMAC_SHA2_224\n");
        md = EVP_sha224();
        ret->key_length = 16;
        ret->tagbytes = 28;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_HMAC_SHA2_256:
        text(log_fp, "Create IBV_HDR_HMAC_SHA2_256\n");
        md = EVP_sha256();
        ret->key_length = 16;
        ret->tagbytes = 32;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_HMAC_SHA2_384:
        text(log_fp, "Create IBV_HDR_HMAC_SHA2_384\n");
        md = EVP_sha384();
        ret->key_length = 16;
        ret->tagbytes = 48;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_HMAC_SHA2_512:
        text(log_fp, "Create IBV_HDR_HMAC_SHA2_512\n");
        md = EVP_sha512();
        ret->key_length = 16;
        ret->tagbytes = 64;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_HMAC_SHA3_224:
        text(log_fp, "Create IBV_HDR_HMAC_SHA3_224\n");
        md = EVP_sha3_224();
        ret->key_length = 16;
        ret->tagbytes = 28;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_HMAC_SHA3_256:
        text(log_fp, "Create IBV_HDR_HMAC_SHA3_256\n");
        md = EVP_sha3_256();
        ret->key_length = 16;
        ret->tagbytes = 32;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_HMAC_SHA3_384:
        text(log_fp, "Create IBV_HDR_HMAC_SHA3_384\n");
        md = EVP_sha3_384();
        ret->key_length = 16;
        ret->tagbytes = 48;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_HMAC_SHA3_512:
        text(log_fp, "Create IBV_HDR_HMAC_SHA3_512\n");
        md = EVP_sha3_512();
        ret->key_length = 16;
        ret->tagbytes = 64;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_PCKT_HMAC_SHA1_160:
        text(log_fp, "Create IBV_PCKT_HMAC_SHA1_160\n");
        md = EVP_sha1();
        ret->key_length = 16;
        ret->tagbytes = 20;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_HMAC_SHA2_224:
        text(log_fp, "Create IBV_PCKT_HMAC_SHA2_224\n");
        md = EVP_sha224();
        ret->key_length = 16;
        ret->tagbytes = 28;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_HMAC_SHA2_256:
        text(log_fp, "Create IBV_PCKT_HMAC_SHA2_256\n");
        md = EVP_sha256();
        ret->key_length = 16;
        ret->tagbytes = 32;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_HMAC_SHA2_384:
        text(log_fp, "Create IBV_PCKT_HMAC_SHA2_384\n");
        md = EVP_sha384();
        ret->key_length = 16;
        ret->tagbytes = 48;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_HMAC_SHA2_512:
        text(log_fp, "Create IBV_PCKT_HMAC_SHA2_512\n");
        md = EVP_sha512();
        ret->key_length = 16;
        ret->tagbytes = 64;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_HMAC_SHA3_224:
        text(log_fp, "Create IBV_PCKT_HMAC_SHA3_224\n");
        md = EVP_sha3_224();
        ret->key_length = 16;
        ret->tagbytes = 28;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_HMAC_SHA3_256:
        text(log_fp, "Create IBV_PCKT_HMAC_SHA3_256\n");
        md = EVP_sha3_256();
        ret->key_length = 16;
        ret->tagbytes = 32;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_HMAC_SHA3_384:
        text(log_fp, "Create IBV_PCKT_HMAC_SHA3_384\n");
        md = EVP_sha3_384();
        ret->key_length = 16;
        ret->tagbytes = 48;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_HMAC_SHA3_512:
        text(log_fp, "Create IBV_PCKT_HMAC_SHA3_512\n");
        md = EVP_sha3_512();
        ret->key_length = 16;
        ret->tagbytes = 64;
        ret->dtype = data_t::PACKET;
        break;

      default:
        text(log_fp, "Unknown crypto name\n");
        goto error;
    }
    assert(md != NULL && "md cannot be null for hmac");

#ifdef CLASSICHMAC

    if (key == NULL) {
      text(log_fp, "Key is NULL \n");
      key = (unsigned char *)malloc(ret->key_length);
      dummy_key = true;
    }
    if (!HMAC_Init_ex(hmacctx, key, ret->key_length, md, NULL)) {
      text(log_fp, "Failed init\n");
      HMAC_CTX_free(hmacctx);
      goto error;
    }
    if (dummy_key) {
      free((unsigned char *)key);
    }
#else
    ctrl_ign_unsupported(hmacctx, EVP_MAC_CTRL_SET_MD, md);
    if (key) {
      EVP_MAC_ctrl(hmacctx, EVP_MAC_CTRL_SET_KEY, key, ret->key_length);
    }

#endif

  } else if (cryptoname < IBV_AEAD_AES_96) {
    text(log_fp, "[SECURITY] : Create CMAC ctx \n");
    EVP_CIPHER_CTX *CIPHERctx = EVP_CIPHER_CTX_new();
    if (CIPHERctx == NULL) {
      text(log_fp, "error EVP_CIPHER_CTX_new\n");
      return ret;
    }
    ret->type = crypto_type_t::CMAC;
    ret->ctx = CIPHERctx;

    uint32_t ivlen = 12;
    const EVP_CIPHER *cipher = NULL;

    switch (cryptoname) {
      case IBV_HDR_CMAC_AES_96:
        text(log_fp, "Create IBV_HDR_CMAC_AES_96\n");
        cipher = EVP_aes_128_ocb();
        ret->key_length = 16;
        ret->tagbytes = 12;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_CMAC_AES_128:
        text(log_fp, "Create IBV_HDR_CMAC_AES_128\n");
        cipher = EVP_aes_128_ocb();
        ret->key_length = 16;
        ret->tagbytes = 16;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_CMAC_AES_192:
        text(log_fp, "Create IBV_HDR_CMAC_AES_192\n");
        cipher = EVP_aes_192_ocb();
        ret->key_length = 24;
        ret->tagbytes = 16;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_CMAC_AES_256:
        text(log_fp, "Create IBV_HDR_CMAC_AES_256\n");
        cipher = EVP_aes_256_ocb();
        ret->key_length = 32;
        ret->tagbytes = 16;
        ret->dtype = data_t::HEADER;
        break;
      case IBV_HDR_CMAC_CHACHA20_POLY1305:
        text(log_fp, "Create IBV_HDR_CMAC_CHACHA20_POLY1305\n");
        cipher = EVP_chacha20_poly1305();
        ret->key_length = 32;
        ret->tagbytes = 16;
        ret->dtype = data_t::HEADER;
        ivlen = 12;
        break;
      case IBV_PCKT_CMAC_AES_96:
        text(log_fp, "Create IBV_PCKT_CMAC_AES_96\n");
        cipher = EVP_aes_128_ocb();
        ret->key_length = 16;
        ret->tagbytes = 12;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_CMAC_AES_128:
        text(log_fp, "Create IBV_PCKT_CMAC_AES_128\n");
        cipher = EVP_aes_128_ocb();
        ret->key_length = 16;
        ret->tagbytes = 16;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_CMAC_AES_192:
        text(log_fp, "Create IBV_PCKT_CMAC_AES_192\n");
        cipher = EVP_aes_192_ocb();
        ret->key_length = 24;
        ret->tagbytes = 16;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_CMAC_AES_256:
        text(log_fp, "Create IBV_PCKT_CMAC_AES_256\n");
        cipher = EVP_aes_256_ocb();
        ret->key_length = 32;
        ret->tagbytes = 16;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_PCKT_CMAC_CHACHA20_POLY1305:
        text(log_fp, "Create IBV_PCKT_CMAC_CHACHA20_POLY1305\n");
        cipher = EVP_chacha20_poly1305();
        ret->key_length = 32;
        ret->tagbytes = 16;
        ret->dtype = data_t::PACKET;
        ivlen = 12;
        break;
      default:
        text(log_fp, "Unknown crypto name\n");
        goto error;
    }

    assert(cipher != NULL && "cipher cannot be null");

    if (!EVP_EncryptInit_ex(CIPHERctx, cipher, NULL, key, NULL)) {
      EVP_CIPHER_CTX_free(CIPHERctx);
      goto error;
    }

    if (!EVP_CIPHER_CTX_ctrl(CIPHERctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL)) {
      text(log_fp, "error EVP_CIPHER_CTX_ctrl\n");
      EVP_CIPHER_CTX_free(CIPHERctx);
      goto error;
    }
    //   if( ret->tagbytes == 12)
    if (!EVP_CIPHER_CTX_ctrl(CIPHERctx, EVP_CTRL_AEAD_SET_TAG, ret->tagbytes,
                             NULL)) {
      text(log_fp, "error EVP_CIPHER_CTX_ctrl\n");
      EVP_CIPHER_CTX_free(CIPHERctx);
      goto error;
    }

  } else {
    text(log_fp, "[SECURITY] : Create AES ctx \n");
    EVP_CIPHER_CTX *CIPHERctx = EVP_CIPHER_CTX_new();
    if (CIPHERctx == NULL) {
      text(log_fp, "error EVP_CIPHER_CTX_new\n");
      return ret;
    }
    ret->type = crypto_type_t::AEDS;
    ret->ctx = CIPHERctx;

    uint32_t ivlen = 12;
    const EVP_CIPHER *cipher = NULL;

    switch (cryptoname) {
      case IBV_AEAD_AES_96:
        text(log_fp, "Create IBV_AEAD_AES_96\n");
        cipher = EVP_aes_128_ocb();
        ret->key_length = 16;
        ret->tagbytes = 12;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_AEAD_AES_128:
        text(log_fp, "Create IBV_AEAD_AES_128\n");
        cipher = EVP_aes_128_ocb();
        ret->key_length = 16;
        ret->tagbytes = 16;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_AEAD_AES_192:
        text(log_fp, "Create IBV_AEAD_AES_192\n");
        cipher = EVP_aes_192_ocb();
        ret->key_length = 24;
        ret->tagbytes = 16;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_AEAD_AES_256:
        text(log_fp, "Create IBV_AEAD_AES_256\n");
        cipher = EVP_aes_256_ocb();
        ret->key_length = 32;
        ret->tagbytes = 16;
        ret->dtype = data_t::PACKET;
        break;
      case IBV_AEAD_CHACHA20_POLY1305:
        text(log_fp, "Create IBV_AEAD_CHACHA20_POLY1305\n");
        cipher = EVP_chacha20_poly1305();
        ret->key_length = 32;
        ret->tagbytes = 16;
        ret->dtype = data_t::PACKET;
        ivlen = 12;
        break;
      default:
        text(log_fp, "Unknown crypto name\n");
        goto error;
    }

    assert(cipher != NULL && "cipher cannot be null");

    if (!EVP_EncryptInit_ex(CIPHERctx, cipher, NULL, key, NULL)) {
      EVP_CIPHER_CTX_free(CIPHERctx);
      goto error;
    }

    if (!EVP_CIPHER_CTX_ctrl(CIPHERctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL)) {
      text(log_fp, "error EVP_CIPHER_CTX_ctrl\n");
      EVP_CIPHER_CTX_free(CIPHERctx);
      goto error;
    }

    if (!EVP_CIPHER_CTX_ctrl(CIPHERctx, EVP_CTRL_AEAD_SET_TAG, ret->tagbytes,
                             NULL)) {
      text(log_fp, "error EVP_CIPHER_CTX_ctrl\n");
      EVP_CIPHER_CTX_free(CIPHERctx);
      goto error;
    }
  }
  return ret;

error:
  free(ret);
  return NULL;
}

uint32_t onsend(ibv_secure_ctx *ctx, unsigned char *header, uint32_t headersize,
                unsigned char *buf, uint32_t bufsize, unsigned char *key = NULL,
                unsigned char *memkey = NULL) {
  ctx->sendnonce += 2;

  uint32_t len = 0;
  int intlen = 0;

  if (ctx->type == crypto_type_t::NOSECURITY) {
    // nothing
    return 0;  // 0 tagsize
  } else if (ctx->type == crypto_type_t::HMAC) {
    text(log_fp, "Sign HMAC with nonce %u\n", (uint32_t)(ctx->sendnonce));

#ifdef CLASSICHMAC
    uint32_t key_length = 0;
    if (key) {
      key_length = ctx->key_length;
    }

    HMAC_Init_ex((HMAC_CTX *)ctx->ctx, key, key_length, 0, NULL);
    HMAC_Update((HMAC_CTX *)ctx->ctx, (const unsigned char *)&(ctx->sendnonce),
                sizeof(ctx->sendnonce));
    HMAC_Update((HMAC_CTX *)ctx->ctx, (const unsigned char *)header,
                headersize);
    if (memkey) {
      HMAC_Update((HMAC_CTX *)ctx->ctx, memkey, KDFKEYSIZE);
    }
    if (ctx->dtype == data_t::PACKET && bufsize > 0) {
      HMAC_Update((HMAC_CTX *)ctx->ctx, (const unsigned char *)buf, bufsize);
    }

    HMAC_Final((HMAC_CTX *)ctx->ctx, header + headersize, &len);

#else
    uint64_t hugelen = 0;
    if (key) {
      EVP_MAC_ctrl((EVP_MAC_CTX *)ctx->ctx, EVP_MAC_CTRL_SET_KEY, key,
                   ctx->key_length);
    }
    EVP_MAC_init((EVP_MAC_CTX *)ctx->ctx);
    EVP_MAC_update((EVP_MAC_CTX *)ctx->ctx,
                   (const unsigned char *)&(ctx->sendnonce),
                   sizeof(ctx->sendnonce));
    EVP_MAC_update((EVP_MAC_CTX *)ctx->ctx, (const unsigned char *)header,
                   headersize);
    if (memkey) {
      EVP_MAC_update((EVP_MAC_CTX *)ctx->ctx, memkey, KDFKEYSIZE);
    }
    if (ctx->dtype == data_t::PACKET && bufsize > 0) {
      EVP_MAC_update((EVP_MAC_CTX *)ctx->ctx, (const unsigned char *)buf,
                     bufsize);
    }

    EVP_MAC_final((EVP_MAC_CTX *)ctx->ctx, header + headersize, &hugelen);
    return (uint32_t)hugelen;
#endif
    return len;
  } else if (ctx->type == crypto_type_t::CMAC) {
    /* Initialise nonce */
    EVP_EncryptInit_ex((EVP_CIPHER_CTX *)ctx->ctx, NULL, NULL, key,
                       (const unsigned char *)&(ctx->sendnonce));
    EVP_EncryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen, header,
                      headersize);
    if (memkey) {
      EVP_EncryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen, memkey,
                        KDFKEYSIZE);
    }
    if (ctx->dtype == data_t::PACKET && bufsize > 0) {
      EVP_EncryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen,
                        (const unsigned char *)buf, bufsize);
    }

    /* Finalise: note get no output for GCM */
    EVP_EncryptFinal_ex((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen);
    /* Get tag */
    EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)ctx->ctx, EVP_CTRL_AEAD_GET_TAG,
                        ctx->tagbytes, header + headersize);

    return ctx->tagbytes;

  } else {
    /* Initialise nonce */
    EVP_EncryptInit_ex((EVP_CIPHER_CTX *)ctx->ctx, NULL, NULL, key,
                       (const unsigned char *)&(ctx->sendnonce));
    EVP_EncryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen,
                      (const unsigned char *)header, headersize);
    if (memkey) {
      EVP_EncryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen, memkey,
                        KDFKEYSIZE);
    }
    if (bufsize > 0) {
      EVP_EncryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, buf, &intlen,
                        (const unsigned char *)buf, bufsize);
      /* Finalise: note get no output for GCM */
      EVP_EncryptFinal_ex((EVP_CIPHER_CTX *)ctx->ctx, buf + intlen, &intlen);
    } else {
      EVP_EncryptFinal_ex((EVP_CIPHER_CTX *)ctx->ctx, 0, &intlen);
    }

    /* Get tag */
    EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)ctx->ctx, EVP_CTRL_AEAD_GET_TAG,
                        ctx->tagbytes, header + headersize);
    return ctx->tagbytes;
  }
  return false;
}

// tempbuf is some shared buffer for temporal computations.
bool onreceive(ibv_secure_ctx *ctx, unsigned char *header, uint32_t headersize,
               unsigned char *buf, uint32_t bufsize, unsigned char *tempbuf,
               unsigned char *key = NULL, unsigned char *memkey = NULL) {
  ctx->recvnonce += 2;
  text(log_fp, "Check MAC onreceive\n");
  uint32_t len = 0;
  int intlen = 0;

  if (ctx->type == crypto_type_t::NOSECURITY) {
    // nothing
    return true;
  } else if (ctx->type == crypto_type_t::HMAC) {
    text(log_fp, "Check HMAC on %u\n", (uint32_t)ctx->recvnonce);

#ifdef CLASSICHMAC
    uint32_t key_length = 0;
    if (key) {
      text(log_fp, "set key \n");
      key_length = ctx->key_length;
    }

    HMAC_Init_ex((HMAC_CTX *)ctx->ctx, key, key_length, 0, NULL);
    HMAC_Update((HMAC_CTX *)ctx->ctx, (const unsigned char *)&(ctx->recvnonce),
                sizeof(ctx->recvnonce));
    HMAC_Update((HMAC_CTX *)ctx->ctx, (const unsigned char *)header,
                headersize);
    if (memkey) {
      HMAC_Update((HMAC_CTX *)ctx->ctx, memkey, KDFKEYSIZE);
    }

    if (ctx->dtype == data_t::PACKET && bufsize > 0) {
      HMAC_Update((HMAC_CTX *)ctx->ctx, (const unsigned char *)buf, bufsize);
    }

    HMAC_Final((HMAC_CTX *)ctx->ctx, tempbuf, &len);
    printBytes(tempbuf, len);
    bool success = ((uint32_t)len == ctx->tagbytes) &&
                   (memcmp(tempbuf, header + headersize, len) == 0);
#else
    uint64_t hugelen = 0;
    if (key) {
      EVP_MAC_ctrl((EVP_MAC_CTX *)ctx->ctx, EVP_MAC_CTRL_SET_KEY, key,
                   ctx->key_length);
    }
    EVP_MAC_init((EVP_MAC_CTX *)ctx->ctx);
    EVP_MAC_update((EVP_MAC_CTX *)ctx->ctx,
                   (const unsigned char *)&(ctx->recvnonce),
                   sizeof(ctx->recvnonce));
    EVP_MAC_update((EVP_MAC_CTX *)ctx->ctx, (const unsigned char *)header,
                   headersize);
    if (memkey) {
      EVP_MAC_update((EVP_MAC_CTX *)ctx->ctx, memkey, KDFKEYSIZE);
    }

    if (ctx->dtype == data_t::PACKET && bufsize > 0) {
      EVP_MAC_update((EVP_MAC_CTX *)ctx->ctx, (const unsigned char *)buf,
                     bufsize);
    }

    EVP_MAC_final((EVP_MAC_CTX *)ctx->ctx, tempbuf, &hugelen);
    bool success = ((uint32_t)hugelen == ctx->tagbytes) &&
                   (memcmp(tempbuf, header + headersize, len) == 0);
#endif

    return success;

  } else if (ctx->type == crypto_type_t::CMAC) {
    /* Initialise nonce */
    EVP_DecryptInit_ex((EVP_CIPHER_CTX *)ctx->ctx, NULL, NULL, key,
                       (const unsigned char *)&(ctx->recvnonce));
    EVP_DecryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen, header,
                      headersize);
    if (memkey) {
      EVP_DecryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen, memkey,
                        KDFKEYSIZE);
    }
    if (ctx->dtype == data_t::PACKET && bufsize > 0) {
      EVP_DecryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen, buf,
                        bufsize);
    }
    EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)ctx->ctx, EVP_CTRL_AEAD_SET_TAG,
                        ctx->tagbytes, header + headersize);
    int rv = EVP_DecryptFinal_ex((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen);

    return rv > 0;

  } else {
    int rv = 0;
    /* Initialise nonce */
    EVP_DecryptInit_ex((EVP_CIPHER_CTX *)ctx->ctx, NULL, NULL, key,
                       (const unsigned char *)&(ctx->recvnonce));
    EVP_DecryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen, header,
                      headersize);
    if (memkey) {
      EVP_DecryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen, memkey,
                        KDFKEYSIZE);
    }
    if (bufsize > 0) {
      EVP_DecryptUpdate((EVP_CIPHER_CTX *)ctx->ctx, buf, &intlen, buf, bufsize);
      EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)ctx->ctx, EVP_CTRL_AEAD_SET_TAG,
                          ctx->tagbytes, header + headersize);
      rv = EVP_DecryptFinal_ex((EVP_CIPHER_CTX *)ctx->ctx, buf + intlen,
                               &intlen);
    } else {
      EVP_CIPHER_CTX_ctrl((EVP_CIPHER_CTX *)ctx->ctx, EVP_CTRL_AEAD_SET_TAG,
                          ctx->tagbytes, header + headersize);
      rv = EVP_DecryptFinal_ex((EVP_CIPHER_CTX *)ctx->ctx, NULL, &intlen);
    }

    return rv > 0;
  }
  return false;
}

ibv_kdf_ctx initkdf(ibv_kdf_type type, const unsigned char *masterkey,uint32_t key_length) {
  if (key_length != KDFKEYSIZE) {
    info(log_fp, "Error! KDFKEYSIZE\n");
    return NULL;
  }
  if (type == ibv_kdf_type::KDF_CMAC_AES_128) {
    bool dummy_key = false;
    CMAC_CTX *cmacctx = CMAC_CTX_new();
    if (masterkey == NULL) {
      text(log_fp, "Install dummykey \n");
      masterkey = (unsigned char *)malloc(KDFKEYSIZE);
      dummy_key = true;
    }

    if (!CMAC_Init(cmacctx, masterkey, KDFKEYSIZE, EVP_aes_128_cbc(), NULL)) {
      CMAC_CTX_free(cmacctx);
      cmacctx = NULL;
      text(log_fp, "Error! KDF\n");
    }
    if (dummy_key) {
      free((unsigned char *)masterkey);
    }
    return cmacctx;
  }
  text(log_fp, "Error! Unknown KDF type\n");
  return NULL;
}

/**
 * @description: 密钥分发函数
 * @param {ibv_kdf_ctx} ctx 指向KDF上下文的指针，用于在派生过程中保存状态和计算中间值
 * @param {unsigned char} *input 指向输入数据的指针，即要用于生成新密钥的原始数据。
 * @param {uint32_t} inputsize 输入数据的字节数
 * @param {unsigned char} *outputkey 指向派生密钥的指针，即生成的新密钥存储的地址。
 * @param {uint32_t} outputsize 派生密钥的字节数
 * @return {*}
 */
int kdf(ibv_kdf_ctx ctx, unsigned char *input, uint32_t inputsize,
        unsigned char *outputkey, uint32_t outputsize) {
  size_t len = 0;

  CMAC_Init(ctx, 0, 0, 0, NULL);
  CMAC_Update(ctx, (const unsigned char *)input, inputsize);

  CMAC_Final(ctx, outputkey, &len);
  if (len == 0) {
    text(log_fp, "Error! KDF final \n");
  }
  return 0;
}

/**
 * @description: 带初始密钥的密钥分发函数
 * @return {*}
 */
inline int kdf_with_key(ibv_kdf_ctx ctx, unsigned char *inputkey,
                        uint32_t keysize, unsigned char *input,
                        uint32_t inputsize, unsigned char *outputkey,
                        uint32_t outputsize) {
  size_t len = 0;

  CMAC_Init(ctx, inputkey, keysize, 0, NULL);
  CMAC_Update(ctx, (const unsigned char *)input, inputsize);

  CMAC_Final(ctx, outputkey, &len);
  if (len == 0) {
    text(log_fp, "Error! KDF final \n");
  }
  return 0;
}
//mark:2023/4/20
inline int calculate_memory_MAC(uint64_t regionstart, uint32_t offset,
                                uint32_t length, uint32_t region_size,
                                unsigned char *key_copy, ibv_kdf_ctx kdfctx) {
  // assert(region_size!=0);
  int depth = 0;
  printBytes(key_copy, KDFKEYSIZE);
  uint32_t middle = next_pow2(region_size) >> 1;
  uint32_t half = middle;
  uint128_t tohash;

  while (!(offset < middle && offset + length > middle) &&
         half != 1) {  // while our region does not cross middle
    depth++;
    half = half >> 1;
    uint32_t newmiddle = (offset >= middle)
                             ? middle + half
                             : middle - half;  // calcualte new middle
    text(log_fp, "%u %u (%" PRIu64 " : %" PRIu64 ") \n", middle, newmiddle,
         regionstart + middle, regionstart + newmiddle);
    tohash =
        (((uint128_t)regionstart + middle) << 64) + regionstart + newmiddle;
    middle = newmiddle;
    kdf_with_key(kdfctx, key_copy, KDFKEYSIZE, (unsigned char *)&tohash,
                 sizeof(tohash), key_copy, KDFKEYSIZE);
    printBytes(key_copy, KDFKEYSIZE);
    // KDF(ctx, &tohash, 16, key_copy, key_copy); // input key and write to the
    // same buffer
  }
  text(log_fp, "======\n");
  text(log_fp, " %" PRIu64 " %" PRIu64 " \n", regionstart + offset,
       regionstart + offset + length);
  tohash =
      (((uint128_t)regionstart + offset) << 64) + regionstart + offset + length;
  kdf_with_key(kdfctx, key_copy, KDFKEYSIZE, (unsigned char *)&tohash,
               sizeof(tohash), key_copy, KDFKEYSIZE);
  printBytes(key_copy, KDFKEYSIZE);
  text(log_fp, "\n\n\n");
  return depth;
}

subregion_t grant_subregion(uint64_t regionstart, uint32_t offset,
                            uint32_t length, uint32_t region_size,
                            unsigned char *key_copy, ibv_kdf_ctx kdfctx) {
  // assert(region_size!=0);
  printBytes(key_copy, KDFKEYSIZE);
  uint32_t middle = next_pow2(region_size) >> 1;
  uint32_t half = middle;
  uint128_t tohash = 0;

  while (!(offset < middle && offset + length > middle) &&
         half != 1) {  // while our region does not cross middle
    half = half >> 1;
    uint32_t newmiddle = (offset >= middle)
                             ? middle + half
                             : middle - half;  // calcualte new middle
    text(log_fp, "%u %u (%" PRIu64 " : %" PRIu64 ") \n", middle, newmiddle,
         regionstart + middle, regionstart + newmiddle);
    tohash =
        (((uint128_t)regionstart + middle) << 64) + regionstart + newmiddle;
    middle = newmiddle;
    kdf_with_key(kdfctx, key_copy, KDFKEYSIZE, (unsigned char *)&tohash,
                 sizeof(tohash), key_copy, KDFKEYSIZE);
    printBytes(key_copy, KDFKEYSIZE);
  }
  text(log_fp, "Grant %u %u (%" PRIu64 " : %" PRIu64 ") \n", middle - half,
       middle + half, regionstart + middle - half, regionstart + middle + half);
  printBytes(key_copy, KDFKEYSIZE);
  text(log_fp, "\n\n\n");
  return {regionstart + middle - half, 2 * half};
}
