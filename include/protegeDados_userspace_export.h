#pragma pack(1)
#ifndef _PROTEGEDADOS_USERSPACE_EXPORT_H
#define _PROTEGEDADOS_USERSPACE_EXPORT_H

#include "hashtable.h"

#ifdef __cplusplus
extern "C" 
{
#endif

//
//  Default and Maximum number of threads.
//

#define SCANNER_DEFAULT_REQUEST_COUNT       5
#define SCANNER_DEFAULT_THREAD_COUNT        2
#define SCANNER_MAX_THREAD_COUNT            64
	
//
//  Context passed to worker threads
//

enum scanner_flags {
    BLOCK_USB_EXE = 0x1,
    BLOCK_USB_WRITE = 0x2,
	BLOCK_USB_USE	= 0x4,
    NO_FLAGS = 0,
    ALL_FLAGS = BLOCK_USB_EXE | BLOCK_USB_WRITE 
};
#ifndef __SCANUSER_H__
typedef void *HANDLE;
#endif
typedef struct _SCANNER_THREAD_CONTEXT {
	hash_table_t *md5_table;
	enum scanner_flags flags;
	uint32_t id;
	uint32_t local_version;
//#ifdef __SCANUSER_H__
	uint32_t thread_count;
    HANDLE Port;
    HANDLE Completion;
	HANDLE mutex_update_lock[SCANNER_MAX_THREAD_COUNT];
//#endif // __SCANUSER_H__
} SCANNER_THREAD_CONTEXT, *PSCANNER_THREAD_CONTEXT;


int _cdecl executaProtegeDados (__in int threads_number, __in int requests_number, __in int *need_to_stop);

int _cdecl install_minifilter (void);
int _cdecl uninstall_minifilter (void);

#ifdef __cplusplus
}  /* end extern "C" */
#endif

#endif
