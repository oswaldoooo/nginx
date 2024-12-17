#include "encrypt.h"
#include <stdio.h>
#include <string.h>
static unsigned char public_key[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8BMH5/isHAQmQhpjNKbI\n"
    "DQGYlczB/se+XbdpmXKLrWtg4a5jd8k+Kl5p3kSneU5ZQuCAYoUgc9EGwS89pAET\n"
    "6ZEG4QPOHYKIV89X7k0SS31SRJ5o32lG+fBH6O+N+RkBammRbPXRWNoM7PTycXQe\n"
    "1o0KIVTtMPaPKB1Zt9nhoCtLxLi4wOqwHESZweKQpFSy7s7yLmmpmadTnynhHp43\n"
    "lHEDmGLY4gc812Nt2/IqsFq9L3xIuRckE1Ff3DgstyW9IuQot/ZSZIEFjcP1SAg0\n"
    "SP8XNFROE7QT/XTlSEobHqO2ISVjoXL8XV8QD9Tt8CxhDXGExvGootcVlJ4Ox8te\n"
    "BwIDAQAB\n"
    "-----END PUBLIC KEY-----";
int encrypt_some(const char *file_name) {
  return encrypt_conf_file(public_key, sizeof(public_key), file_name,
                           strlen(file_name));
}

int main(int argv, const char **argc) {
  if (argv < 2) {
    fprintf(stderr, "not set encrypt file");
    return 1;
  }
  return encrypt_some(argc[1]);
}