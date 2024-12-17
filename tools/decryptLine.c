#include "encrypt.h"
#include <stdio.h>
#include <string.h>
int decrypt_some(const char *file_name) {
  return decrypt_conf_file((unsigned char *)file_name, strlen(file_name));
}

int main(int argv, const char **argc) {
  if(argv<2){
    fprintf(stderr,"not set decrypt target");
    return 1;
  }
  return decrypt_some(argc[1]);
}