#ifndef _ENCRYPT_H_INCLUDED_
#define _ENCRYPT_H_INCLUDED_
int decrypt_conf_file(unsigned char *file, unsigned long size);
int destroy_decrypt_file(unsigned char *file, unsigned long size);
int encrypt_conf_file(const unsigned char* pubkey,unsigned long pubkey_size,const char *file, unsigned long size);
#endif