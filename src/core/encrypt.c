#include "encrypt.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <stdio.h>
#include <string.h>
static const char rsa_pri_key[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDwEwfn+KwcBCZC\n"
    "GmM0psgNAZiVzMH+x75dt2mZcouta2DhrmN3yT4qXmneRKd5TllC4IBihSBz0QbB\n"
    "Lz2kARPpkQbhA84dgohXz1fuTRJLfVJEnmjfaUb58Efo7435GQFqaZFs9dFY2gzs\n"
    "9PJxdB7WjQohVO0w9o8oHVm32eGgK0vEuLjA6rAcRJnB4pCkVLLuzvIuaamZp1Of\n"
    "KeEenjeUcQOYYtjiBzzXY23b8iqwWr0vfEi5FyQTUV/cOCy3Jb0i5Ci39lJkgQWN\n"
    "w/VICDRI/xc0VE4TtBP9dOVIShseo7YhJWOhcvxdXxAP1O3wLGENcYTG8aii1xWU\n"
    "ng7Hy14HAgMBAAECggEAYUF8avOZGbJuo0nYVayZD3fNjiYIkwPtMT8Lxw+Z2TPO\n"
    "aC7C+fRrPDPKVLJgXCqqy4ZyTDcdOf38bAeMw6NyIyVO8ZoehmLqhBQpzY6oci9/\n"
    "Q/AekR8vkzJNl2Zwj/Ca27aPpOICoKmZIedrTh3aHlW9vFoQysyfmwMk5O+d0Unf\n"
    "/9oE/JGUZxWT0wSe8dVARJGMupl5Z46O1X4leXan73tIXF2NmWjuBytyhU2dRsXi\n"
    "z6i4rT5SggeL8q4Y3BCiZT08BlhRjrOME9I+wKtjpDHxaIAWEIB1+pHHrBk8v7lQ\n"
    "xTKAIpXFWKaxuuNf/FiZ4D80Ywr0+byp6Edk7SMd6QKBgQD8Q3KAkHy0BkQSBG0k\n"
    "Fhx1QKJzJMEZ8nXhFe4j61LmwRqFh2b892brPsDzI/JwwXL3cVk2wvg131QFCUvZ\n"
    "R5ikSmyAlL7dbvo0o4rHc1AQ/hkZMW9q+SJ2CZiqppC9m4B7yZQGMpqT3dRmIbwu\n"
    "wpkvb6V9gvZLgnWoGo3lFOfmDwKBgQDzoV0pBVjONzNwH//XL6QCA+B+A6KD7XyC\n"
    "a99ezixnPOZ/dU8D4TDfdCmk68R6XzBsChM78dIBjoaw88FFukFlLP73L1auBvk1\n"
    "3fDRMpJnfz292MMG/yQPhSOpg+pjd3+npJpX+EJ13jvvXSu/j8Rli/ycMvvhJKBv\n"
    "LeKyeHrAiQKBgBDd+aP7BTuMR7Tkst980v5MChCk3nx7p8IbE0c3jt16/+j5ursj\n"
    "V7BXC9O2DZnYdXVyEMMGmk4P1rBXhMjMbrpdd4/JYlGv/+7RGJBpd2sLcmYq1gZT\n"
    "DijST3DpnjfvU9HzEoCvlYJZjMAfdVOzE0cGsgwIW6uE15Ub4Wz1zuOlAoGAMcP1\n"
    "bqqr8DuwYyf2L7OIkezOz47YhJBfTZjRYOFGirQS9Vg2ErnOLObiltCeKs0E7BzG\n"
    "vwjvd+fwNXclNKQONaeSUVW3JAdCorE6PtFQvJluODht5iD58b2lgjvzBexkBA+I\n"
    "g42vrbn+ji9+/ztTx9ZnfFShxOShbPR3iTM5B9kCgYEAlR2qZeOVV2sNt7PKZmC7\n"
    "xrzItte28BgyayoJdkws7zv6k+hv2WnsxkZb+XgeWH9ga2JUKA9IeOOfposGlJHj\n"
    "dAhe3ve3x/TaWJ1TC+MUmRBcCl51kWl+t86Q7sHUP/y3513iq/pccMBWlwCmrqW+\n"
    "XzUDBzQMfiOhpql1eEHysWA=\n"
    "-----END PRIVATE KEY-----";
void handleError(const char *words) {
  char buff[256] = {0};
  ERR_error_string_n(ERR_get_error(), buff, 256);
  printf("%s get error %s", words, buff);
}
int decrypt_conf_file(unsigned char *file, unsigned long size) {
  unsigned char file_name[size + 5];
  memmove(file_name, file, size);
  memmove(file_name + size, ".tmp", 4);
  file_name[size + 4] = 0;
  FILE *fd = fopen((char *)file, "rb");
  if (fd == NULL) {
    return -1;
  }
  FILE *dfd = fopen((char *)file_name, "wb");
  if (dfd == NULL) {
    fclose(fd);
    return -1;
  }
  BIO *bio = BIO_new_mem_buf(rsa_pri_key, strlen(rsa_pri_key));
  if (bio == NULL) {
    fclose(fd);
    fclose(dfd);
    return -3;
  }
  EVP_PKEY *epkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  if (epkey == NULL) {
    fclose(fd);
    fclose(dfd);
    BIO_free(bio);
    return -3;
  }
  if (EVP_PKEY_base_id(epkey) != EVP_PKEY_RSA) {
    fclose(fd);
    fclose(dfd);
    EVP_PKEY_free(epkey);
    BIO_free(bio);
    return -2;
  }
  int bits = EVP_PKEY_get_bits(epkey);
  EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(epkey, NULL);
  if (ectx==NULL){
    fclose(fd);
    fclose(dfd);
    EVP_PKEY_free(epkey);
    BIO_free(bio);
    return -3;
  }
  bits = bits / 8;
  unsigned char chunk[bits];
  unsigned char out_chunk[bits];
  size_t read_size;
  size_t out_len;
  size_t total_read = 0;
  size_t total_decrypt = 0;
  int ok=EVP_PKEY_decrypt_init(ectx);
  EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_PKCS1_PADDING);
  while (1) {
    read_size = fread(chunk, 1, bits, fd);
    total_read += read_size;
    if (read_size != (size_t)bits) {
      break;
    }
    out_len=bits;
    ok = EVP_PKEY_decrypt(ectx, out_chunk, &out_len, chunk, read_size);
    if (ok <= 0||out_len==0) {
      handleError("decrypt content failed");
      break;
    }
    total_decrypt += out_len;
    printf("read %ld decrypt %ld read size %ld\n", total_read, total_decrypt,read_size);
    
    fwrite(out_chunk, 1, out_len, dfd);
  }
  fclose(fd);
  fclose(dfd);
  EVP_PKEY_CTX_free(ectx);
  EVP_PKEY_free(epkey);
  BIO_free(bio);
  return 0;
}
int destroy_decrypt_file(unsigned char *file, unsigned long size) {
  char buff[size + 5];
  memmove(buff, file, size);
  memmove(buff + size, ".tmp", 4);
  buff[size + 4] = 0;
  return remove(buff);
}

int encrypt_conf_file(const unsigned char *pubkey, unsigned long pubkey_size,
                      const char *file, unsigned long size) {
  FILE *fd = fopen(file, "rb");
  if (fd == NULL) {
    return -1;
  }
  char file_name[size + 4];
  memmove(file_name, file, size);
  memmove(file_name + size, ".en", 3);
  file_name[size + 3] = 0;
  FILE *dfd = fopen(file_name, "wb");
  if (dfd == NULL) {
    fclose(fd);
    return -1;
  }
  BIO *bio = BIO_new_mem_buf(pubkey, (int)pubkey_size);
  if (bio == NULL) {
    fclose(fd);
    fclose(dfd);
    return -2;
  }
  EVP_PKEY *epkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  if (epkey == NULL) {
    handleError("read bio pubkey");
    fclose(fd);
    fclose(dfd);
    BIO_free(bio);
    return -2;
  }
  if (EVP_PKEY_base_id(epkey) != EVP_PKEY_RSA) {
    fclose(fd);
    fclose(dfd);
    EVP_PKEY_free(epkey);
    BIO_free(bio);
    return -2;
  }
  EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(epkey, NULL);
  if (ectx == NULL) {
    handleError("pkey ctx new");
    fclose(fd);
    fclose(dfd);
    EVP_PKEY_free(epkey);
    BIO_free(bio);
    return -2;
  }
  EVP_PKEY_encrypt_init(ectx);
  int bits = EVP_PKEY_get_bits(epkey);
  bits = bits / 8;
  unsigned char chunk[bits - 11];
  unsigned char out_chunk[bits];
  size_t out_len;
  long read_size;
  size_t total_read_size = 0;
  size_t total_encrypt_size = 0;
  EVP_PKEY_encrypt_init(ectx);
  EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_PKCS1_PADDING);
  while (1) {
    read_size = fread(chunk, 1, bits - 11, fd);
    if (read_size <= 0) {
      break;
    }
    total_read_size += read_size;
    read_size = EVP_PKEY_encrypt(ectx, out_chunk, &out_len, chunk, read_size);
    if (read_size < 0) {
      handleError("encrypt failed");
      break;
    }
    total_encrypt_size += out_len;
    fwrite(out_chunk, 1, out_len, dfd);
  }
  fclose(fd);
  fclose(dfd);
  EVP_PKEY_CTX_free(ectx);
  EVP_PKEY_free(epkey);
  BIO_free(bio);
  printf("read %ld encrypt %ld\n", total_read_size, total_encrypt_size);
  return 0;
}