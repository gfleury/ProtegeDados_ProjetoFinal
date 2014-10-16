// filehash.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define WDK
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashtable.h"
#include "arquivoHash.h"

#define HASH_CHUNKS_SIZE 1024*16

//#pragma warning(default : 4296)

#define MAX(x,y) (((x) > (y)) ? (x) : (y))

uint64_t  _cdecl compute_hash_simple(FILE * handle)
{
	uint64_t hash, fsize;
	uint64_t tmp, i;

	fseek(handle, 0, SEEK_END);
	fsize = ftell(handle);
	fseek(handle, 0, SEEK_SET);

	hash = fsize;
	for(tmp = 0, i = 0; i < 65536/sizeof(tmp) && fread((char*)&tmp, sizeof(tmp), 1, handle); hash += tmp, i++);
	fseek(handle, (long)MAX(0, fsize - 65536), SEEK_SET);
	for(tmp = 0, i = 0; i < 65536/sizeof(tmp) && fread((char*)&tmp, sizeof(tmp), 1, handle); hash += tmp, i++);

	return hash;
}

md5_byte_t  *  _cdecl calcula_hash_md5_arquivo(uint64_t fsize, unsigned char *head, uint64_t head_size, unsigned char *tail, uint64_t tail_size, md5_byte_t *digest) {
	md5_state_t state;
	//unsigned long long buffer[1024*16+1]; //16 Kbytes
	//int read_bytes;

	// Init md5 hash
	md5_init(&state);

	// Add Size to hash
	md5_append(&state, (const md5_byte_t *)&fsize, sizeof(uint64_t)/sizeof(char));

	// Add Head to hash
	md5_append(&state, (const md5_byte_t *)head, (int)head_size);

	// Add Head to hash
	md5_append(&state, (const md5_byte_t *)tail, (int)tail_size);

	md5_finish(&state, digest);

	return (digest);
}

md5_byte_t  *  _cdecl calcula_hash_md5_path(const wchar_t *path, int path_size, md5_byte_t *digest) {
	md5_state_t state;
	/*int opt;
	
	printf ("\nSIZE t=%d\n", path_size);
	
	printf ("\STRING t=%ls\n", path);
	
	for (opt=0; opt < path_size; opt++) {
		printf ("0x%02x, ", path[opt]);		
	}

	printf("\n");
	*/
	// Init md5 hash
	md5_init(&state);

	// Add Head to hash
	md5_append(&state, path, path_size);
	
	md5_finish(&state, digest);

	return (digest);
}

md5_byte_t * _cdecl make_local_hashes_w(const wchar_t *argv) {
	char c[1024];
	int tmpwchar_size;
	int tmppath_size = wcslen (argv) + 1;

	wcstombs_s (&tmpwchar_size, c, tmppath_size, argv, _TRUNCATE);

	return make_local_hashes(c);
}

md5_byte_t * _cdecl make_local_hashes(const char *argv) {
	FILE * handle;
	uint64_t myhash;
	static md5_byte_t digest[16] = { 0 };
	unsigned char head[1024*16], tail[1024*16];
	uint64_t head_size, tail_size;
	int i;
	uint64_t fsize;

	i = fopen_s(&handle, argv, "rb");

	if (!handle) {
		printf("Error openning file! \n");
		return NULL;
	}

	myhash = compute_hash_simple(handle);  
	printf("%I64x\n", myhash);

	fseek(handle, 0, SEEK_END);
	fsize = ftell(handle);
	fseek(handle, 0, SEEK_SET);

	// Read file head 
	head_size = fread(head, 1, 16384, handle);

	// Jump to end of file
	fseek(handle, (long)MAX(0, (int)fsize - HASH_CHUNKS_SIZE), SEEK_SET);

	// Read file tail 
	tail_size = fread(tail, 1, 16384, handle);

	printf ("Offset %d %d %d %d\n", fsize, (long)MAX(0, (int)fsize - HASH_CHUNKS_SIZE), tail_size, head_size);

	calcula_hash_md5_arquivo(fsize, head, head_size, tail, tail_size, digest);

	printf (" { ");

	for (i=0; i < 16; i++) {
		printf ("0x%02x, ", digest[i]);
	}

	printf (" } \n");

	fclose(handle);
	return digest;
}

md5_byte_t * _cdecl make_name_hashes(wchar_t *argv) {
	uint64_t myhash;
	static md5_byte_t digest[16] = { 0 };
	
	printf ("SIZE STR = %d\n", wcslen(argv)*2);

	calcula_hash_md5_path(argv, wcslen(argv)*2, digest);

	return digest;
}
