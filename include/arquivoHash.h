/**
 * License GPLv3+
 * @file hashtable.h
 * @brief a simple hash table implementation
 * @author Ankur Shrivastava
 */
#ifndef _FILEHASH_H
#define _FILEHASH_H

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include "md5.h"
#include "protegeDados_userspace_export.h"

#ifdef WDK
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
#else 
#include <c:\Program Files (x86)\Microsoft Visual Studio 10.0\VC\include\stdint.h>
#endif

typedef enum load_type { HEADERS, FULL } load_type;

typedef struct hash_info {
	unsigned char hash_name[16];
	unsigned char hash_arquivo[16];
	unsigned char acesso_livre_ids[32];
} hash_info, *hash_infop;

typedef struct hash_list {
	unsigned char id;
	hash_info hash_info;
} hash_list, *hash_listp;

#ifdef __cplusplus
extern "C" {  /* end extern "C" */
#endif

uint64_t  _cdecl compute_hash_simple(FILE * handle);
md5_byte_t *_cdecl make_local_hashes(const char* argv);
md5_byte_t *_cdecl make_local_hashes_w (const wchar_t* argv);
md5_byte_t *_cdecl make_name_hashes(wchar_t* argv);
md5_byte_t *_cdecl calcula_hash_md5_arquivo(uint64_t fsize, unsigned char *head, uint64_t head_size, unsigned char *tail, uint64_t tail_size, md5_byte_t *digest);
md5_byte_t *_cdecl calcula_hash_md5_path(const wchar_t *path, int path_size, md5_byte_t *digest);

int _cdecl save_hashtable (PSCANNER_THREAD_CONTEXT Context);
int _cdecl load_hashtable (PSCANNER_THREAD_CONTEXT Context, load_type type);
int _cdecl command_line_control (int argc, char *argv[]);

#ifdef __cplusplus
}  /* end extern "C" */
#endif
#endif
