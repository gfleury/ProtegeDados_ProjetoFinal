/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scanUser.c

Abstract:

    This file contains the implementation for the main function of the
    user application piece of scanner.  This function is responsible for
    actually scanning file contents.

Environment:

    User mode

--*/
#ifndef WDK
#define WDK
#endif

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include "scanuk.h"
#include "protegeDados_userspace.h"
#include "protegeDados_userspace_export.h"
#include "hashtable.h"
#include "arquivoHash.h"
//#include <dontuse.h>
#include <C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\include\Psapi.h>

DWORD ScannerWorker(__in PSCANNER_THREAD_CONTEXT Context) {
    PSCANNER_NOTIFICATION notification;
    SCANNER_REPLY_MESSAGE replyMessage;
    PSCANNER_MESSAGE message;
    LPOVERLAPPED pOvlp;
    BOOL result;
    DWORD outSize;
    HRESULT hr;
    ULONG_PTR key;
	DWORD dwWaitResult, my_id = Context->thread_count;

	FILE * handle;
	uint64_t myhash;
	md5_byte_t digest[16];
	md5_byte_t name_digest[16];
	hash_list *hl = NULL;
	wchar_t *nome_lookup = NULL;

	int base_file_name_size;
	wchar_t *base_file_name;
	wchar_t *base_dir_name;
	wchar_t *p;
	//wchar_t *file_exe[] = { L".exe", L"bat", L".com", L".inf", L".sys", L".dll", L'\0' };

	hash_table_t *md5_table;
	hash_table_t *nome_table;

	md5_table = Context->md5_table;

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

    while (TRUE) {
		
		hl = NULL;
#pragma warning(pop)

        //
        //  Poll for messages from the filter component to scan.
        //

        result = GetQueuedCompletionStatus( Context->Completion, &outSize, &key, &pOvlp, INFINITE );

        //
        //  Obtain the message: note that the message we sent down via FltGetMessage() may NOT be
        //  the one dequeued off the completion queue: this is solely because there are multiple
        //  threads per single port handle. Any of the FilterGetMessage() issued messages can be
        //  completed in random order - and we will just dequeue a random one.
        //

        message = CONTAINING_RECORD( pOvlp, SCANNER_MESSAGE, Ovlp );

        if (!result) {

            //
            //  An error occured.
            //

            hr = HRESULT_FROM_WIN32( GetLastError() );
            break;
        }

        //printf( "Received message, size %d\n", pOvlp->InternalHigh );

        notification = &message->Notification;

        assert(notification->head_BytesToScan <= SCANNER_READ_BUFFER_SIZE);
        __analysis_assume(notification->head_BytesToScan <= SCANNER_READ_BUFFER_SIZE);
		assert(notification->tail_BytesToScan <= SCANNER_READ_BUFFER_SIZE);
        __analysis_assume(notification->tail_BytesToScan <= SCANNER_READ_BUFFER_SIZE);
		assert(notification->file_name_size <= FILE_NAME_MAX_SIZE);
        __analysis_assume(notification->file_name_size <= FILE_NAME_MAX_SIZE);

		notification->file_name[notification->file_name_size] = L'\0';
		notification->file_name[notification->file_name_size+1] = L'\0';

		base_file_name = (wchar_t *)notification->file_name;
		for (p = (wchar_t *)notification->file_name; *p != L'\0'; p++) {
			if ( *p == L'\\' )
				base_file_name = ++p;
		}

		_wcslwr_s((wchar_t *)notification->file_name,  wcslen((wchar_t *)notification->file_name) + 1);

		base_file_name_size = wcslen(base_file_name)*sizeof(wchar_t);

		calcula_hash_md5_path ((wchar_t *)notification->file_name, notification->file_name_size, name_digest);

		calcula_hash_md5_arquivo(notification->Size, notification->Head, notification->head_BytesToScan, notification->Tail, notification->tail_BytesToScan, digest);

		//////////// Comeco Zona critica //////////////
		dwWaitResult = WaitForSingleObject(Context->mutex_update_lock[my_id], INFINITE);
		 
		hl = (hash_list *)HT_LOOKUP(md5_table, &name_digest);

		result = FALSE;

		if (hl != NULL) {
			
			printf ("ID = %d ####%ls####\n", hl->id, (wchar_t *)notification->file_name);

			if (memcmp (name_digest, hl->hash_info.hash_name, sizeof(name_digest)) == 0) {
			
				if (notification->requestor_pid && hl->hash_info.acesso_livre_ids[0]) {

					HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, notification->requestor_pid);
					if (h != NULL) {
						wchar_t exe_path[2048] = {0};

						if (GetModuleFileNameExW(h, 0, exe_path, sizeof(exe_path) - 1)) {
							wchar_t long_exe_path[2048] = {0};
							md5_byte_t name_digest_exe[16];
							hash_list *hl_exe = NULL;
							if(GetLongPathNameW (exe_path, long_exe_path, 2048)) {
								wchar_t physPath[1024] = { 0 };
								wchar_t finalPath[MAX_PATH];
								wchar_t logicalPath[4] = { 0 };
								int pathSize;

								_wcslwr_s(long_exe_path,  wcslen(long_exe_path) + 1);
								printf ("\tRequestor Name: %ls\n", long_exe_path);

								swprintf(logicalPath, L"%lc%lc", *long_exe_path, *(long_exe_path+1));

								pathSize = QueryDosDeviceW (logicalPath, physPath, 1024);

								physPath[pathSize+1] = '\0';

								pathSize = wcslen (physPath) + wcslen(long_exe_path);

								swprintf(finalPath, L"%ls%ls", physPath, (long_exe_path+2));
								_wcslwr_s(finalPath,  wcslen(finalPath) + 1);
								printf ("\tRequestor Name: %ls\n", finalPath);

								calcula_hash_md5_path (finalPath, wcslen(finalPath)*2, name_digest_exe);
								hl_exe = (hash_list *)HT_LOOKUP(md5_table, &name_digest_exe);
								if (hl_exe != NULL) {
									int xx;
									printf ("\tRequestor ID: %d\n", hl_exe->id);
									for (xx = 0; xx < 32 && hl->hash_info.acesso_livre_ids[xx]; xx++) {
										result = TRUE;
										printf ("\tIDs liberados: %d\n", hl->hash_info.acesso_livre_ids[xx]);
										if (hl->hash_info.acesso_livre_ids[xx] == hl_exe->id) {
											md5_byte_t *md5_hash_exe = NULL;
											md5_hash_exe = make_local_hashes_w (long_exe_path);
											if (md5_hash_exe != NULL && memcmp (md5_hash_exe, hl_exe->hash_info.hash_arquivo, sizeof(hl_exe->hash_info.hash_arquivo)) == 0) {
												result = FALSE;
												break;
											} else {
												printf ("##### HASH DE BINARIO MODIFICADO, BINARIO NAO PODE ABRIR ARQUIVO. #####\n");
												break;
											}
										}
									}
									
								}
							}
						}
						CloseHandle (h);
					} 

				} else if (memcmp (digest, hl->hash_info.hash_arquivo, sizeof(digest)) != 0) {	
					printf ("========== Arquivo foi alterado, e seu hash nao bate com a baseline! ==========\n");
					result = TRUE;

				}

			} 

			
#ifndef _DEBUG
#define _DEBUG 1
#endif
#ifdef _DEBUG
		if (_DEBUG) {
			
			int opt;
			for (opt=0; opt < 16; opt++) {
				printf ("%02x, ", digest[opt]);
			}
			printf ("\n");

			for (opt=0; opt < 16; opt++) {
				printf ("%02x, ", name_digest[opt]);
			}

			printf ("\n");
			
			printf ("Dumping MSG:\n");
			printf ("\tFile Name: %ls \n\tSize: %d \n", notification->file_name, base_file_name_size);
			printf ("\tBase File Name: %ls\n", base_file_name);
			printf ("\tRequestor PID: %d\n", notification->requestor_pid);
		
			printf ("\tFile Size: %d\n", notification->Size);
			printf ("\tTipo do Volume: %d\n", notification->volume_type);
			printf ("\tFile Stream Mode: %s\n", notification->file_mode == CREATE_MODE ? "CREATE" : notification->file_mode == WRITE_MODE ? "WRITE" : notification->file_mode == CLEANUP_MODE ? "CLEANUP" : "Unknow");
			printf ("\tHead bytes: %d\n", notification->head_BytesToScan);
			printf ("\tTail bytes: %d\n\n", notification->tail_BytesToScan);
		}
#endif
		}

		ReleaseMutex(Context->mutex_update_lock[my_id]);
		//////////// Fim Zona critica //////////////


		replyMessage.ReplyHeader.Status = 0;
		replyMessage.ReplyHeader.MessageId = message->MessageHeader.MessageId;

		//
		//  Precisamos inverter o boleano -- resultado 'e true caso seja liberado o acesso ao arquivo e false caso o acesso seja bloqueado
		//

		replyMessage.Reply.SafeToOpen = !result;

		//printf( "Respondendo mensagem, SafeToOpen: %d\n", replyMessage.Reply.SafeToOpen );

        hr = FilterReplyMessage( Context->Port,
                                 (PFILTER_REPLY_HEADER) &replyMessage,
                                 sizeof( replyMessage ) );

        if (SUCCEEDED( hr )) {

           // printf( "Mensagem de resposta enviada\n" );

        } else {

            printf( "Erro enviando mensagem de resposta. Erro = 0x%X\n", hr );
            break;
        }

        memset( &message->Ovlp, 0, sizeof( OVERLAPPED ) );


        hr = FilterGetMessage( Context->Port,
                               &message->MessageHeader,
                               FIELD_OFFSET( SCANNER_MESSAGE, Ovlp ),
                               &message->Ovlp );

        if (hr != HRESULT_FROM_WIN32( ERROR_IO_PENDING )) {

            break;
		}

	}

    if (!SUCCEEDED( hr )) {

        if (hr == HRESULT_FROM_WIN32( ERROR_INVALID_HANDLE )) {

            //
            //  Scanner port disconncted.
            //

            //printf( "Scanner: Port is disconnected, probably due to scanner filter unloading.\n" );

        } else {

            //printf( "Scanner: Unknown error occured. Error = 0x%X\n", hr );
        }
    }

    free( message );

    return hr;
}

int _cdecl executaProtegeDados (__in int threads_number, __in int requests_number, __in int *need_to_stop) {

    DWORD requestCount = SCANNER_DEFAULT_REQUEST_COUNT;
    DWORD threadCount = SCANNER_DEFAULT_THREAD_COUNT;
    HANDLE threads[SCANNER_MAX_THREAD_COUNT];
    SCANNER_THREAD_CONTEXT context;
    HANDLE port, completion;
    PSCANNER_MESSAGE msg;
    DWORD threadId;
    HRESULT hr;
    DWORD i, j;

	if (threads_number < SCANNER_DEFAULT_THREAD_COUNT)
		threadCount = threads_number;

	if (requests_number < SCANNER_DEFAULT_THREAD_COUNT)
		requestCount = requests_number;

	
	//
	// Inicializa politicas, Carrega Hashes salvos
	//

	context.md5_table = hash_table_new(MODE_COPY);

	load_hashtable (&context, FULL);

	if (_DEBUG && FALSE) {
		// DEBUG
		int opt = 0;
		md5_byte_t teste[16] = { 0xc1, 0xe7, 0x2a, 0xa4, 0x18, 0x07, 0xa1, 0x58, 0x55, 0x71, 0x12, 0x53, 0x11, 0xb5, 0x91, 0x03  };//{ 0x07, 0x0d, 0xef, 0xd5, 0xad, 0x0a, 0x60, 0x10, 0x92, 0x49, 0xa0, 0xfc, 0xbc, 0x85, 0x51, 0x63  };//{ 0x75, 0x22, 0x18, 0xb5, 0xf5, 0x8b, 0x6b, 0xee, 0x62, 0xa5, 0x2b, 0xa6, 0xed, 0x99, 0xd3, 0xf7  };
		
		// FILL HASHTABLES!
		hash_table_add(context.md5_table, &teste, 16*sizeof(md5_byte_t), &teste, 16*sizeof(md5_byte_t));

		context.flags = BLOCK_USB_WRITE | BLOCK_USB_EXE;
		context.id = 1;
		
		//save_hashtable (&context);
		// final Debug
	}



	//
    //  Open a commuication channel to the filter
    //

    printf( "Scanner: Connecting to the filter ...\n" );

    hr = FilterConnectCommunicationPort( ScannerPortName,
                                         0,
                                         NULL,
                                         0,
                                         NULL,
                                         &port );

    if (IS_ERROR( hr )) {

        printf( "ERROR: Connecting to filter port: 0x%08x\n", hr );
        return 2;
    }

    //
    //  Create a completion port to associate with this handle.
    //

    completion = CreateIoCompletionPort( port,
                                         NULL,
                                         0,
                                         threadCount );

    if (completion == NULL) {

        printf( "ERROR: Creating completion port: %d\n", GetLastError() );
        CloseHandle( port );
        return 3;
    }

    printf( "Scanner: Port = 0x%p Completion = 0x%p\n", port, completion );

    context.Port = port;
    context.Completion = completion;
	

    //
    //  Create specified number of threads.
    //

    for (i = 0; i < threadCount; i++) {

		context.mutex_update_lock[i] = CreateMutex (NULL, FALSE, NULL);
		context.thread_count = i;
        threads[i] = CreateThread( NULL,
                                   0,
                                   (LPTHREAD_START_ROUTINE)ScannerWorker,
                                   &context,
                                   0,
                                   &threadId );

        if (threads[i] == NULL) {

            //
            //  Couldn't create thread.
            //

            hr = GetLastError();
            printf( "ERROR: Couldn't create thread: %d\n", hr );
            goto main_cleanup;
        }

        for (j = 0; j < requestCount; j++) {

            //
            //  Allocate the message.
            //

#pragma prefast(suppress:__WARNING_MEMORY_LEAK, "msg will not be leaked because it is freed in ScannerWorker")
            msg = (PSCANNER_MESSAGE) malloc( sizeof( SCANNER_MESSAGE ) );

            if (msg == NULL) {
                hr = ERROR_NOT_ENOUGH_MEMORY;
                goto main_cleanup;
            }

            memset( &msg->Ovlp, 0, sizeof( OVERLAPPED ) );
			
			//
            //  Request messages from the filter driver.
            //

            hr = FilterGetMessage( port,
                                   &msg->MessageHeader,
                                   FIELD_OFFSET( SCANNER_MESSAGE, Ovlp ), 
								   &msg->Ovlp );

            if (hr != HRESULT_FROM_WIN32( ERROR_IO_PENDING )) {
                free( msg );
                goto main_cleanup;
            }
        }
    }

    hr = S_OK;

	do  {
		SCANNER_THREAD_CONTEXT new_context;
		
		if (load_hashtable(&new_context, HEADERS) == TRUE) {
			BOOLEAN reload = FALSE;

			if (new_context.id != context.id) 
				reload = TRUE;
			
			if (!reload && new_context.local_version > context.local_version)
				reload = TRUE;

			if (reload) {
				DWORD c, dwWaitResult = WaitForMultipleObjectsEx(i, context.mutex_update_lock, TRUE, INFINITE, FALSE);  

				hash_table_delete (context.md5_table);

				context.md5_table = hash_table_new(MODE_COPY);

				load_hashtable (&context, FULL);

				for (c = 0; c < i; c++)
					ReleaseMutex(context.mutex_update_lock[c]);

				printf ("Arquivo de politicas recarregado!\n");
			}
		}
		j = WaitForMultipleObjectsEx( i, threads, TRUE, 5000, FALSE );
		if (*need_to_stop == TRUE) {
			int c;
			for (c = 0; c < i; c++) {
				TerminateThread (threads[i], 0xf00f);
				CloseHandle (threads[i]);
			}
		}
	} while (j == WAIT_TIMEOUT);

main_cleanup:

	hash_table_delete (context.md5_table);

    printf( "Scanner:  All done. Result = 0x%08x\n", hr );

	CloseHandle(context.mutex_update_lock);
    CloseHandle( port );
    CloseHandle( completion );

    return hr;
}

