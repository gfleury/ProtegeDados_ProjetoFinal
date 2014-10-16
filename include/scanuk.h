/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

    scanuk.h

Abstract:

    Header file which contains the structures, type definitions,
    constants, global variables and function prototypes that are
    shared between kernel and user mode.

Environment:

    Kernel & user mode

--*/

#ifndef __SCANUK_H__
#define __SCANUK_H__

//
//  Name of port used to communicate
//

const PWSTR ScannerPortName = L"\\ScannerPort";

#define HASH_CHUNKS_SIZE 1024*16
#define SCANNER_READ_BUFFER_SIZE   HASH_CHUNKS_SIZE+16 //16k + 1 byte (so precaucao e alinhamento, integrar com todos os projetos o tamanho do hash a ser feito)
#define FILE_NAME_MAX_SIZE	1024

#define CREATE_MODE 0xbabe
#define WRITE_MODE  0xbeef
#define CLEANUP_MODE 0xf00f

typedef struct _SCANNER_NOTIFICATION {
    ULONG head_BytesToScan;	// Head size, em bytes, pode ser menor de 16K se o arquivo for menor que 16K
	ULONG tail_BytesToScan; // Tail size in bytes, pode ser menor que 16K ou igual 0K se o arquivo tiver menos de 32K ou menos que 16K
    ULONG Size;             // Tamanho do arquivo
	ULONG file_mode;			 // read/write
	STORAGE_BUS_TYPE bus_type;			 // Tipo do barramento
	ULONG volume_type;			// Tipo do volume, se 'e dispositivo externo/rede ou disco local.
	ULONG requestor_pid;		 // pid do processo pai		
	USHORT file_name_size;        // tamanho do nome do arquivo
    UCHAR Head[SCANNER_READ_BUFFER_SIZE]; // Primeiros 16Kbytes do arquivo
	UCHAR Tail[SCANNER_READ_BUFFER_SIZE]; // Ultimos 16Kbytes do arquivo
	UCHAR file_name[FILE_NAME_MAX_SIZE]; // Nome do arquivo aberto
} SCANNER_NOTIFICATION, *PSCANNER_NOTIFICATION;

typedef struct _SCANNER_REPLY {
    BOOLEAN SafeToOpen;
} SCANNER_REPLY, *PSCANNER_REPLY;

#endif //  __SCANUK_H__


