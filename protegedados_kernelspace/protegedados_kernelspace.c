/*++

Copyright (c) 1999-2002  Microsoft Corporation

Module Name:

scanner.c

Abstract:

This is the main module of the scanner filter.

This filter scans the data in a file before allowing an open to proceed.  This is similar
to what virus checkers do.

Environment:

Kernel mode

--*/

#include <fltKernel.h>
#include <suppress.h>
#include <stdio.h>
#include <Ntddstor.h>
#include "scanuk.h"
#include "protegeDados_kernelspace.h"

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//
//  Structure that contains all the global data structures
//  used throughout the scanner.
//

SCANNER_DATA ScannerData;

//
//  This is a static list of file name extensions files we are interested in scanning
//

//
//  Prototipos das funcoes
//

NTSTATUS ScannerPortConnect (__in PFLT_PORT ClientPort, __in_opt PVOID ServerPortCookie, __in_bcount_opt(SizeOfContext) PVOID ConnectionContext, 
							 __in ULONG SizeOfContext, __deref_out_opt PVOID *ConnectionCookie);

VOID ScannerPortDisconnect (__in_opt PVOID ConnectionCookie);

NTSTATUS ScannerpScanFileInUserMode (__in PFLT_INSTANCE Instance, __in PFILE_OBJECT FileObject, __out PBOOLEAN SafeToOpen, 
									 __in  PFLT_CALLBACK_DATA CallbackData, __in  PUCHAR file_name, __in  USHORT file_name_lenght);


//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, ScannerInstanceSetup)
#pragma alloc_text(PAGE, ScannerPreCreate)
#pragma alloc_text(PAGE, ScannerPortConnect)
#pragma alloc_text(PAGE, ScannerPortDisconnect)
#endif


//
//  Constant FLT_REGISTRATION structure for our filter.  This
//  initializes the callback routines our filter wants to register
//  for.  This is only used to register with the filter manager
//

const FLT_OPERATION_REGISTRATION Callbacks[] = {

	{ IRP_MJ_CREATE,
	0,
	ScannerPreCreate,
	ScannerPostCreate},

	{ IRP_MJ_CLEANUP,
	0,
	ScannerPreCleanup,
	NULL},

	{ IRP_MJ_WRITE,
	0,
	ScannerPreWrite,
	NULL},

	{ IRP_MJ_OPERATION_END }
};


const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

	{ FLT_STREAMHANDLE_CONTEXT,
	0,
	NULL,
	sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
	'chBS' },

	{ FLT_INSTANCE_CONTEXT,             
	0,                                
	NULL,                 
	sizeof(SCANNER_INSTANCE_HANDLE_CONTEXT),         
	'chBx' },  

	{ FLT_CONTEXT_END }
};

const FLT_REGISTRATION FilterRegistration = {

	sizeof( FLT_REGISTRATION ),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags
	ContextRegistration,                //  Context Registration.
	Callbacks,                          //  Operation callbacks
	ScannerUnload,                      //  FilterUnload
	ScannerInstanceSetup,               //  InstanceSetup
	ScannerQueryTeardown,               //  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete
	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};

////////////////////////////////////////////////////////////////////////////
//
//    Filter initialization and unload routines.
//
////////////////////////////////////////////////////////////////////////////

NTSTATUS DriverEntry (__in PDRIVER_OBJECT DriverObject, __in PUNICODE_STRING RegistryPath) {
		/*++

	Routine Description:

	This is the initialization routine for the Filter driver.  This
	registers the Filter with the filter manager and initializes all
	its global data structures.

	Arguments:

	DriverObject - Pointer to driver object created by the system to
	represent this driver.

	RegistryPath - Unicode string identifying where the parameters for this
	driver are located in the registry.

	Return Value:

	Returns STATUS_SUCCESS.
	--*/
	OBJECT_ATTRIBUTES oa;
	UNICODE_STRING uniString;
	PSECURITY_DESCRIPTOR sd;
	NTSTATUS status;
	const UNICODE_STRING *ext;

	DbgPrint( "!!! protegedados.sys -- Entrando no driver" );

	UNREFERENCED_PARAMETER( RegistryPath );

	//
	//  Register with filter manager.
	//
	try {

		status = FltRegisterFilter( DriverObject, &FilterRegistration, &ScannerData.Filter );

		if (!NT_SUCCESS( status )) {
			DbgPrint( "!!! protegedados.sys -- FltRegisterFilter falhou=%d", status );
			return status;
		}

		//
		//  Create a communication port.
		//

		RtlInitUnicodeString( &uniString, ScannerPortName );

		//
		//  We secure the port so only ADMINs & SYSTEM can acecss it.
		//

		status = FltBuildDefaultSecurityDescriptor( &sd, FLT_PORT_ALL_ACCESS );

		if (NT_SUCCESS( status )) {

			InitializeObjectAttributes( &oa,
				&uniString,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL,
				sd );

			status = FltCreateCommunicationPort( ScannerData.Filter,
				&ScannerData.ServerPort,
				&oa,
				NULL,
				ScannerPortConnect,
				ScannerPortDisconnect,
				NULL,
				1 );
			//
			//  Free the security descriptor in all cases. It is not needed once
			//  the call to FltCreateCommunicationPort() is made.
			//

			FltFreeSecurityDescriptor( sd );

			if (NT_SUCCESS( status )) {

				//
				//  Start filtering I/O.
				//
				DbgPrint( "!!! protegedados.sys -- Iniciando FltStartFiltering=%d", status );
				status = FltStartFiltering( ScannerData.Filter );

				if (NT_SUCCESS( status )) {	
					return status;
				}

				DbgPrint( "!!! protegedados.sys -- FltStartFiltering falhou=%d", status );
				FltCloseCommunicationPort( ScannerData.ServerPort );
			}
		}

	} finally {

		if (!NT_SUCCESS( status ) ) {
			DbgPrint( "!!! protegedados.sys -- finally falhou=%d", status );
			if (NULL != ScannerData.ServerPort) {
				FltCloseCommunicationPort( ScannerData.ServerPort );
			}

			if (NULL != ScannerData.Filter) {
				FltUnregisterFilter( ScannerData.Filter );
			}


		}
	}

	DbgPrint( "!!! protegedados.sys -- Saindo DriverEntry=%d", status );
	return status;
}


NTSTATUS ScannerPortConnect (__in PFLT_PORT ClientPort, __in_opt PVOID ServerPortCookie,
					__in_bcount_opt(SizeOfContext) PVOID ConnectionContext, __in ULONG SizeOfContext, __deref_out_opt PVOID *ConnectionCookie) {
	/*++

	Routine Description

	This is called when user-mode connects to the server port - to establish a
	connection

	Arguments

	ClientPort - This is the client connection port that will be used to
	send messages from the filter

	ServerPortCookie - The context associated with this port when the
	minifilter created this port.

	ConnectionContext - Context from entity connecting to this port (most likely
	your user mode service)

	SizeofContext - Size of ConnectionContext in bytes

	ConnectionCookie - Context to be passed to the port disconnect routine.

	Return Value

	STATUS_SUCCESS - to accept the connection

	--*/

	PAGED_CODE();

	UNREFERENCED_PARAMETER( ServerPortCookie );
	UNREFERENCED_PARAMETER( ConnectionContext );
	UNREFERENCED_PARAMETER( SizeOfContext);
	UNREFERENCED_PARAMETER( ConnectionCookie );

	ASSERT( ScannerData.ClientPort == NULL );
	ASSERT( ScannerData.UserProcess == NULL );

	//
	//  Set the user process and port.
	//

	ScannerData.UserProcess = PsGetCurrentProcess();
	ScannerData.UserProcessId = PsGetProcessId(ScannerData.UserProcess);
	ScannerData.ClientPort = ClientPort;

	DbgPrint( "!!! protegedados.sys --- UserSpace conectado, port=0x%p ProcessID: %d Thread: %d\n", ClientPort,  ScannerData.UserProcessId, ScannerData.UserProcess);

	return STATUS_SUCCESS;
}


VOID ScannerPortDisconnect(__in_opt PVOID ConnectionCookie)
	/*++

	Routine Description

	This is called when the connection is torn-down. We use it to close our
	handle to the connection

	Arguments

	ConnectionCookie - Context from the port connect routine

	Return value

	None

	--*/
{
	UNREFERENCED_PARAMETER( ConnectionCookie );

	PAGED_CODE();

	DbgPrint( "!!! protegedados.sys --- disconectou, port=0x%p\n", ScannerData.ClientPort );

	//
	//  Close our handle to the connection: note, since we limited max connections to 1,
	//  another connect will not be allowed until we return from the disconnect routine.
	//

	FltCloseClientPort( ScannerData.Filter, &ScannerData.ClientPort );

	//
	//  Reset the user-process field.
	//

	ScannerData.UserProcess = NULL;
	ScannerData.UserProcessId = NULL;
}


NTSTATUS ScannerUnload (__in FLT_FILTER_UNLOAD_FLAGS Flags)
	/*++

	Routine Description:

	This is the unload routine for the Filter driver.  This unregisters the
	Filter with the filter manager and frees any allocated global data
	structures.

	Arguments:

	None.

	Return Value:

	Returns the final status of the deallocation routines.

	--*/
{
	UNREFERENCED_PARAMETER( Flags );

	//
	//  Close the server port.
	//

	FltCloseCommunicationPort( ScannerData.ServerPort );

	//
	//  Unregister the filter
	//

	FltUnregisterFilter( ScannerData.Filter );

	//fclose (hLogFile);
	return STATUS_SUCCESS;
}


NTSTATUS ScannerInstanceSetup (__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_SETUP_FLAGS Flags,
							   __in DEVICE_TYPE VolumeDeviceType, __in FLT_FILESYSTEM_TYPE VolumeFilesystemType)
	/*++

	Routine Description:

	This routine is called by the filter manager when a new instance is created.
	We specified in the registry that we only want for manual attachments,
	so that is all we should receive here.

	Arguments:

	FltObjects - Describes the instance and volume which we are being asked to
	setup.

	Flags - Flags describing the type of attachment this is.

	VolumeDeviceType - The DEVICE_TYPE for the volume to which this instance
	will attach.

	VolumeFileSystemType - The file system formatted on this volume.

	Return Value:

	FLT_NOTIFY_STATUS_ATTACH              - we wish to attach to the volume
	FLT_NOTIFY_STATUS_DO_NOT_ATTACH       - no, thank you

	--*/
{
	PSCANNER_INSTANCE_HANDLE_CONTEXT instance_context = NULL;
	NTSTATUS status;

	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Flags );
	UNREFERENCED_PARAMETER( VolumeFilesystemType );
	

	PAGED_CODE();

	DbgPrint( "!!! protegedados.sys -- ScannerInstanceSetup %d", VolumeDeviceType);

	ASSERT( FltObjects->Filter == ScannerData.Filter );

	//
	// Define contexto da instancia, para checagem da midia, se eh usb e etc..
	//

	status = FltAllocateContext( ScannerData.Filter,
			FLT_INSTANCE_CONTEXT,
			sizeof(SCANNER_INSTANCE_HANDLE_CONTEXT),
			NonPagedPool,
			&instance_context );

	if (NT_SUCCESS(status)) {
		PIRP irp;
		IO_STATUS_BLOCK ioStatus;
		KEVENT kevent;
		CHAR buf[512];
		STORAGE_PROPERTY_QUERY propQuery;
		PSTORAGE_DEVICE_DESCRIPTOR devDesc;
		PDEVICE_OBJECT DeviceObject;

		propQuery.PropertyId = StorageDeviceProperty;
		propQuery.QueryType = PropertyStandardQuery;
		devDesc = (PSTORAGE_DEVICE_DESCRIPTOR) &buf[0];
		status = FltGetDiskDeviceObject( FltObjects->Volume, &DeviceObject );

		if ( NT_SUCCESS( status ) ) {
			KeInitializeEvent (&kevent, NotificationEvent, FALSE );
			irp = IoBuildDeviceIoControlRequest ( IOCTL_STORAGE_QUERY_PROPERTY, DeviceObject, &propQuery, sizeof(propQuery), devDesc, sizeof ( buf ), FALSE, &kevent, &ioStatus );
			if (irp) {
				status = IoCallDriver ( DeviceObject, irp );
				if (status == STATUS_PENDING) {
					KeWaitForSingleObject ( &kevent, Executive, KernelMode, FALSE, NULL );
					status = ioStatus.Status;
				}
			}

			if ( NT_SUCCESS( status ) ) {
				DbgPrint("!!!! protegedados.sys - Nova instancia para busType = %d e eh removivel %d ", devDesc->BusType, devDesc->RemovableMedia);
				instance_context->BusType =  devDesc->BusType;
			}
		}

		// Preenche o contexto
		instance_context->VolumeDeviceType = VolumeDeviceType;
		instance_context->VolumeFilesystemType = VolumeFilesystemType;
		
		(VOID) FltSetInstanceContext( FltObjects->Instance,
			FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
			instance_context,
			NULL );

		FltReleaseContext( instance_context );

	}

	//
	//  Nao attach em volumes de rede
	//

	if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
		DbgPrint( "!!! protegeDados.sys -- ScannerInstanceSetup %d eh Compartilhamento de rede, saindo fora", VolumeDeviceType);
		return STATUS_FLT_DO_NOT_ATTACH;
	}

	return STATUS_SUCCESS;
}


NTSTATUS ScannerQueryTeardown (__in PCFLT_RELATED_OBJECTS FltObjects, __in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
	/*++

	Routine Description:

	This is the instance detach routine for the filter. This
	routine is called by filter manager when a user initiates a manual instance
	detach. This is a 'query' routine: if the filter does not want to support
	manual detach, it can return a failure status

	Arguments:

	FltObjects - Describes the instance and volume for which we are receiving
	this query teardown request.

	Flags - Unused

	Return Value:

	STATUS_SUCCESS - we allow instance detach to happen

	--*/
{
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( Flags );

	return STATUS_SUCCESS;
}


FLT_PREOP_CALLBACK_STATUS ScannerPreCreate (__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
	/*++

	Routine Description:

	Pre create callback.  We need to remember whether this file has been
	opened for write access.  If it has, we'll want to rescan it in cleanup.
	This scheme results in extra scans in at least two cases:
	-- if the create fails (perhaps for access denied)
	-- the file is opened for write access but never actually written to
	The assumption is that writes are more common than creates, and checking
	or setting the context in the write path would be less efficient than
	taking a good guess before the create.

	Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
	operation.

	CompletionContext - Output parameter which can be used to pass a context
	from this pre-create callback to the post-create callback.

	Return Value:

	FLT_PREOP_SUCCESS_WITH_CALLBACK - If this is not our user-mode process.
	FLT_PREOP_SUCCESS_NO_CALLBACK - All other threads.

	--*/
{
	PEPROCESS scan_process = IoThreadToProcess( Data->Thread );
	HANDLE CurProcID    = PsGetProcessId(scan_process);

//	DbgPrint( "!!! scanner.sys -- Entering ScannerPreCreatem process %d",  IoThreadToProcess( Data->Thread ));
	UNREFERENCED_PARAMETER( FltObjects );
	UNREFERENCED_PARAMETER( CompletionContext );

	PAGED_CODE();

	//
	//  See if this create is being done by our user process.
	//
	
	

	if (scan_process == ScannerData.UserProcess || CurProcID == ScannerData.UserProcessId) {

		DbgPrint( "!!! protegedados.sys -- permitindo criacao de processo confiavel (UserSpace) %d\n", CurProcID);

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	} 

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


FLT_POSTOP_CALLBACK_STATUS ScannerPostCreate (__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, 
											  __in FLT_POST_OPERATION_FLAGS Flags)
	/*++

	Routine Description:

	Post create callback.  We can't scan the file until after the create has
	gone to the filesystem, since otherwise the filesystem wouldn't be ready
	to read the file for us.

	Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
	operation.

	CompletionContext - The operation context passed fron the pre-create
	callback.

	Flags - Flags to say why we are getting this post-operation callback.

	Return Value:

	FLT_POSTOP_FINISHED_PROCESSING - ok to open the file or we wish to deny
	access to this file, hence undo the open

	--*/
{
	PSCANNER_STREAM_HANDLE_CONTEXT scannerContext;
	PSCANNER_INSTANCE_HANDLE_CONTEXT instance_context = NULL;
	FLT_POSTOP_CALLBACK_STATUS returnStatus = FLT_POSTOP_FINISHED_PROCESSING;
	PFLT_FILE_NAME_INFORMATION nameInfo;
	NTSTATUS status;
	BOOLEAN safeToOpen;
	UCHAR file_name[FILE_NAME_MAX_SIZE] = { 0 };
	USHORT file_name_length = FILE_NAME_MAX_SIZE;

	UNREFERENCED_PARAMETER( CompletionContext );
	UNREFERENCED_PARAMETER( Flags );

	//
	//  If this create was failing anyway, don't bother scanning now.
	//

	if (!NT_SUCCESS( Data->IoStatus.Status ) ||
		(STATUS_REPARSE == Data->IoStatus.Status)) {

			return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//
	//  Check if we are interested in this file.
	//

	status = FltGetFileNameInformation( Data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		&nameInfo );

	if (!NT_SUCCESS( status )) {

		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	FltParseFileNameInformation( nameInfo );

	RtlCopyMemory (file_name, nameInfo->Name.Buffer, min (FILE_NAME_MAX_SIZE, nameInfo->Name.Length));

	file_name_length = nameInfo->Name.Length;

	//
	//  Release file name info, we're done with it
	//

	FltReleaseFileNameInformation( nameInfo );

	(VOID) ScannerpScanFileInUserMode( FltObjects->Instance,
		FltObjects->FileObject,
		&safeToOpen,
		Data, file_name, file_name_length);

	if (!safeToOpen) {

		//
		//  Ask the filter manager to undo the create.
		//

		DbgPrint( "!!! protegedados.sys -- Acesso negado !!!\n" );

		FltCancelFileOpen( FltObjects->Instance, FltObjects->FileObject );

		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;

		returnStatus = FLT_POSTOP_FINISHED_PROCESSING;

	} else if (FltObjects->FileObject->WriteAccess) {

		//  The create has requested write access, mark to rescan the file.
		//  Allocate the context.
		//

		status = FltAllocateContext( ScannerData.Filter,
			FLT_STREAMHANDLE_CONTEXT,
			sizeof(SCANNER_STREAM_HANDLE_CONTEXT),
			PagedPool,
			&scannerContext );

		if (NT_SUCCESS(status)) {

			//
			//  Set the handle context.
			//

			scannerContext->RescanRequired = TRUE;

//			RtlCopyMemory (scannerContext->file_name, file_name, min(FILE_NAME_MAX_SIZE, file_name_length));
//			scannerContext->file_name_length = file_name_length;

			(VOID) FltSetStreamHandleContext( FltObjects->Instance,
				FltObjects->FileObject,
				FLT_SET_CONTEXT_REPLACE_IF_EXISTS,
				scannerContext,
				NULL );

			//
			//  Normally we would check the results of FltSetStreamHandleContext
			//  for a variety of error cases. However, The only error status 
			//  that could be returned, in this case, would tell us that
			//  contexts are not supported.  Even if we got this error,
			//  we just want to release the context now and that will free
			//  this memory if it was not successfully set.
			//

			//
			//  Release our reference on the context (the set adds a reference)
			//

			FltReleaseContext( scannerContext );
		}
	}

	return returnStatus;
}


FLT_PREOP_CALLBACK_STATUS ScannerPreCleanup (__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
	/*++

	Routine Description:

	Pre cleanup callback.  If this file was opened for write access, we want
	to rescan it now.

	Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
	operation.

	CompletionContext - Output parameter which can be used to pass a context
	from this pre-cleanup callback to the post-cleanup callback.

	Return Value:

	Always FLT_PREOP_SUCCESS_NO_CALLBACK.

	--*/
{
	NTSTATUS status;
	PSCANNER_STREAM_HANDLE_CONTEXT context;
	BOOLEAN safe;

	UNREFERENCED_PARAMETER( Data );
	UNREFERENCED_PARAMETER( CompletionContext );

	status = FltGetStreamHandleContext( FltObjects->Instance,
		FltObjects->FileObject,
		&context );

	if (NT_SUCCESS( status )) {

		if (context->RescanRequired) {
			PFLT_FILE_NAME_INFORMATION nameInfo;

			status = FltGetFileNameInformation( Data,
				FLT_FILE_NAME_NORMALIZED |
				FLT_FILE_NAME_QUERY_DEFAULT,
				&nameInfo );

			if (NT_SUCCESS( status )) {

				FltParseFileNameInformation( nameInfo );

				(VOID) ScannerpScanFileInUserMode( FltObjects->Instance,
					FltObjects->FileObject,
					&safe,
					Data, (PUCHAR)nameInfo->Name.Buffer, nameInfo->Name.Length);

				FltReleaseFileNameInformation( nameInfo );

				if (!safe) {

					DbgPrint( "!!! protegedados.sys -- Acesso negado !!!\n" );
				}

			}

		}

		FltReleaseContext( context );
	}


	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS ScannerPreWrite (__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
	/*++

	Routine Description:

	Pre write callback.  We want to scan what's being written now.

	Arguments:

	Data - The structure which describes the operation parameters.

	FltObject - The structure which describes the objects affected by this
	operation.

	CompletionContext - Output parameter which can be used to pass a context
	from this pre-write callback to the post-write callback.

	Return Value:

	Always FLT_PREOP_SUCCESS_NO_CALLBACK.

	--*/
{
	FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
	NTSTATUS status;
	PSCANNER_NOTIFICATION notification = NULL;
	PSCANNER_STREAM_HANDLE_CONTEXT context = NULL;
	PSCANNER_INSTANCE_HANDLE_CONTEXT instance_context = NULL;
	ULONG replyLength, volumeLength, returnedLength;
	BOOLEAN safe = TRUE;
	PUCHAR buffer;
	PFLT_VOLUME volume = NULL;
	FILE_STANDARD_INFORMATION fileStandardInformation;
	PFLT_FILE_NAME_INFORMATION nameInfo;
	PEPROCESS scan_process = IoThreadToProcess( Data->Thread );
	HANDLE CurProcID    = PsGetProcessId(scan_process);

	UNREFERENCED_PARAMETER( CompletionContext );

	//
	//  If not client port just ignore this write.
	//

	if (ScannerData.ClientPort == NULL || ScannerData.UserProcess == scan_process || ScannerData.UserProcessId == CurProcID) {

		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	status = FltGetStreamHandleContext( FltObjects->Instance,
		FltObjects->FileObject,
		&context );

	if (!NT_SUCCESS( status )) {

		//
		//  We are not interested in this file
		//

		return FLT_PREOP_SUCCESS_NO_CALLBACK;

	}

	//
	//  Use try-finally to cleanup
	//

	try {

		//
		//  Pass the contents of the buffer to user mode.
		//

		if (Data->Iopb->Parameters.Write.Length != 0) {

			//
			//  Get the users buffer address.  If there is a MDL defined, use
			//  it.  If not use the given buffer address.
			//

			if (Data->Iopb->Parameters.Write.MdlAddress != NULL) {

				buffer = MmGetSystemAddressForMdlSafe( Data->Iopb->Parameters.Write.MdlAddress,
					NormalPagePriority );

				//
				//  If we have a MDL but could not get and address, we ran out
				//  of memory, report the correct error
				//

				if (buffer == NULL) {

					Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
					Data->IoStatus.Information = 0;
					returnStatus = FLT_PREOP_COMPLETE;
					leave;
				}

			} else {

				//
				//  Use the users buffer
				//

				buffer  = Data->Iopb->Parameters.Write.WriteBuffer;
			}

			//
			//  In a production-level filter, we would actually let user mode scan the file directly.
			//  Allocating & freeing huge amounts of non-paged pool like this is not very good for system perf.
			//  This is just a sample!
			//

			notification = ExAllocatePoolWithTag( NonPagedPool,
				sizeof( SCANNER_NOTIFICATION ),
				'nacS' );
			
			if (notification == NULL) {
				Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
				Data->IoStatus.Information = 0;
				returnStatus = FLT_PREOP_COMPLETE;
				leave;
			}

			// Get Volume Type
			// pega o contexto da instancia
			status = FltGetInstanceContext( FltObjects->Instance,
				&instance_context );

			if (NT_SUCCESS( status )) {
				notification->bus_type = instance_context->BusType;
				notification->volume_type = instance_context->VolumeDeviceType;

				FltReleaseContext( instance_context );
			}

			// Get FileName
			// Pega nome do arquivo e outras informacoes.

			status = FltGetFileNameInformation( Data,
				FLT_FILE_NAME_NORMALIZED |
				FLT_FILE_NAME_QUERY_DEFAULT,
				&nameInfo );

			if (NT_SUCCESS( status )) {

				FltParseFileNameInformation( nameInfo );
				
				RtlCopyMemory(notification->file_name, nameInfo->Name.Buffer, min(FILE_NAME_MAX_SIZE, nameInfo->Name.Length));

				notification->file_name_size = nameInfo->Name.Length;

				FltReleaseFileNameInformation( nameInfo );
			} else {
				memset(notification->file_name, 0, FILE_NAME_MAX_SIZE);
				notification->file_name_size = 0;
			}

			notification->head_BytesToScan = min( Data->Iopb->Parameters.Write.Length, SCANNER_READ_BUFFER_SIZE );


			status = FltQueryInformationFile(
				FltObjects->Instance,
				FltObjects->FileObject,
				&fileStandardInformation,
				sizeof(FILE_STANDARD_INFORMATION),
				FileStandardInformation,
				&returnedLength
				);

			if(!NT_SUCCESS(status)) {
				DbgPrint("!!! protegedados.sys : ERROR - Impossivel alocar espaco necessario \n");
				leave;
			}

			notification->file_mode = WRITE_MODE; // write
			notification->tail_BytesToScan = 0; // write usa somente um dos buffers
			memset (notification->Tail, 0, SCANNER_READ_BUFFER_SIZE);
			notification->Size = (ULONG) fileStandardInformation.EndOfFile.QuadPart; //fileStandardInformation.AllocationSize.QuadPart; // Passa o tamanho do arquivo
			notification->requestor_pid = FltGetRequestorProcessId(Data);
			
			
			//
			//  The buffer can be a raw user buffer. Protect access to it
			//

			try  {
				RtlCopyMemory( &notification->Head,
					buffer,
					notification->head_BytesToScan );

			} except( EXCEPTION_EXECUTE_HANDLER ) {

				//
				//  Error accessing buffer. Complete i/o with failure
				//

				Data->IoStatus.Status = GetExceptionCode() ;
				Data->IoStatus.Information = 0;
				returnStatus = FLT_PREOP_COMPLETE;
				leave;
			}

			//
			//  Send message to user mode to indicate it should scan the buffer.
			//  We don't have to synchronize between the send and close of the handle
			//  as FltSendMessage takes care of that.
			//

			replyLength = sizeof( SCANNER_REPLY );

			status = FltSendMessage( ScannerData.Filter,
				&ScannerData.ClientPort,
				notification,
				sizeof( SCANNER_NOTIFICATION ),
				notification,
				&replyLength,
				NULL );

			if (STATUS_SUCCESS == status) {

				safe = ((PSCANNER_REPLY) notification)->SafeToOpen;

			} else {

				//
				//  Couldn't send message. This sample will let the i/o through.
				//

				DbgPrint( "!!! protegedados.sys --- PreWrite nao conseguiu enviar mensagem para UserSpace, status 0x%X\n", status );
			}
		}

		if (!safe) {

			//
			//  Block this write if not paging i/o (as a result of course, this scanner will not prevent memory mapped writes of contaminated
			//  strings to the file, but only regular writes). The effect of getting ERROR_ACCESS_DENIED for many apps to delete the file they
			//  are trying to write usually.
			//  To handle memory mapped writes - we should be scanning at close time (which is when we can really establish that the file object
			//  is not going to be used for any more writes)
			//

			DbgPrint( "!!! protegedados.sys -- detectado problema com a escrita !!!\n" );

			if (!FlagOn( Data->Iopb->IrpFlags, IRP_PAGING_IO )) {

				DbgPrint( "!!! protegedados.sys -- bloqueando escrita de arquivo !!!\n" );

				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				returnStatus = FLT_PREOP_COMPLETE;
			}
		}

	} finally {

		if (notification != NULL) {

			ExFreePoolWithTag( notification, 'nacS' );
		}

		if (context) {

			FltReleaseContext( context );
		}
	}

	return returnStatus;
}

//////////////////////////////////////////////////////////////////////////
//  Local support routines.
//
/////////////////////////////////////////////////////////////////////////

NTSTATUS ScannerpScanFileInUserMode (__in PFLT_INSTANCE Instance, __in PFILE_OBJECT FileObject, __out PBOOLEAN SafeToOpen, __in  PFLT_CALLBACK_DATA CallbackData,
									 __in  PUCHAR file_name, __in  USHORT file_name_length)
	/*++

	Routine Description:

	This routine is called to send a request up to user mode to scan a given
	file and tell our caller whether it's safe to open this file.

	Note that if the scan fails, we set SafeToOpen to TRUE.  The scan may fail
	because the service hasn't started, or perhaps because this create/cleanup
	is for a directory, and there's no data to read & scan.

	If we failed creates when the service isn't running, there'd be a
	bootstrapping problem -- how would we ever load the .exe for the service?

	Arguments:

	Instance - Handle to the filter instance for the scanner on this volume.

	FileObject - File to be scanned.

	SafeToOpen - Set to FALSE if the file is scanned successfully and it contains
	foul language.

	Return Value:

	The status of the operation, hopefully STATUS_SUCCESS.  The common failure
	status will probably be STATUS_INSUFFICIENT_RESOURCES.

	--*/

{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID buffer = NULL;
	ULONG bytesRead;
	PSCANNER_NOTIFICATION notification = NULL;
	PSCANNER_INSTANCE_HANDLE_CONTEXT instance_context = NULL;
	FLT_VOLUME_PROPERTIES volumeProps;
	LARGE_INTEGER offset;
	ULONG replyLength, length, returnedLength;
	PFLT_VOLUME volume = NULL;
	FILE_STANDARD_INFORMATION fileStandardInformation;

	*SafeToOpen = TRUE;

	//
	//  If not client port just return.
	//

	if (ScannerData.ClientPort == NULL) {

		return STATUS_SUCCESS;
	}

	try {

		//
		//  Obtain the volume object .
		//

		status = FltGetVolumeFromInstance( Instance, &volume );

		if (!NT_SUCCESS( status )) {

			leave;
		}

		//
		//  Determine sector size. Noncached I/O can only be done at sector size offsets, and in lengths which are
		//  multiples of sector size. A more efficient way is to make this call once and remember the sector size in the
		//  instance setup routine and setup an instance context where we can cache it.
		//

		status = FltGetVolumeProperties( volume,
			&volumeProps,
			sizeof( volumeProps ),
			&length );
		//
		//  STATUS_BUFFER_OVERFLOW can be returned - however we only need the properties, not the names
		//  hence we only check for error status.
		//

		if (NT_ERROR( status )) {

			leave;
		}

		length = max( HASH_CHUNKS_SIZE, volumeProps.SectorSize );

		//
		//  Use non-buffered i/o, so allocate aligned pool
		//

		buffer = FltAllocatePoolAlignedWithTag( Instance,
			NonPagedPool,
			length,
			'nacS' );

		if (NULL == buffer) {

			status = STATUS_INSUFFICIENT_RESOURCES;
			leave;
		}

		notification = ExAllocatePoolWithTag( NonPagedPool,
			sizeof( SCANNER_NOTIFICATION ),
			'nacS' );

		if(NULL == notification) {
			status = STATUS_INSUFFICIENT_RESOURCES;
			leave;
		}

		status = FltQueryInformationFile(
			Instance,
			FileObject,
			&fileStandardInformation,
			sizeof(FILE_STANDARD_INFORMATION),
			FileStandardInformation,
			&returnedLength
			);

		if(!NT_SUCCESS(status)) {
			DbgPrint("!!! protegedados.sys : ERROR - Impossivel alocar espaco necessario !! \n");
			leave;
		}


		// Get Volume Type
		// pega o contexto da instancia
		status = FltGetInstanceContext( Instance,
			&instance_context );

		if (NT_SUCCESS( status )) {
			notification->bus_type = instance_context->BusType;
			notification->volume_type = instance_context->VolumeDeviceType;

			FltReleaseContext( instance_context );
		}

		notification->Size = (ULONG) fileStandardInformation.EndOfFile.QuadPart; //fileStandardInformation.AllocationSize.QuadPart;
		notification->file_mode = CREATE_MODE;
		notification->requestor_pid = FltGetRequestorProcessId (CallbackData);
		RtlCopyMemory (notification->file_name, file_name, min(FILE_NAME_MAX_SIZE, file_name_length));
		notification->file_name_size = file_name_length;

		//
		//  Read the beginning of the file and pass the contents to user mode.
		//

		offset.QuadPart = bytesRead = 0;
		status = FltReadFile( Instance,
			FileObject,
			&offset,
			length,
			buffer,
			FLTFL_IO_OPERATION_NON_CACHED |
			FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			&bytesRead,
			NULL,
			NULL );

		if (NT_SUCCESS( status ) && (0 != bytesRead)) {
			
			notification->head_BytesToScan = (ULONG) bytesRead;
			
			//  Copy only as much as the buffer can hold
			
			RtlCopyMemory( &notification->Head,
				buffer,
				min( notification->head_BytesToScan, SCANNER_READ_BUFFER_SIZE ) );

			// Copy tail 16kbytes
			bytesRead = 0;
			// Define offset para ler apenas os ultimos 16k
			offset.QuadPart = max(0, fileStandardInformation.EndOfFile.QuadPart - HASH_CHUNKS_SIZE);
			
			//DbgPrint("!!! miniscan.sys : offset %d\n", offset.QuadPart);
			status = FltReadFile( Instance,
				FileObject,
				&offset,
				length,
				buffer,
				FLTFL_IO_OPERATION_NON_CACHED |
				FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
				&bytesRead,
				NULL,
				NULL );

			// Copy tail bytes para a strutura a er enviada para userland
			if (NT_SUCCESS( status ) && (0 != bytesRead)) {
				notification->tail_BytesToScan = (ULONG) bytesRead;

				//  Copy only as much as the buffer can hold

				RtlCopyMemory( &notification->Tail,
					buffer,
					min( notification->tail_BytesToScan, SCANNER_READ_BUFFER_SIZE ) );

			} else
				notification->tail_BytesToScan = 0;

			replyLength = sizeof( SCANNER_REPLY );

			status = FltSendMessage( ScannerData.Filter,
				&ScannerData.ClientPort,
				notification,
				sizeof(SCANNER_NOTIFICATION),
				notification,
				&replyLength,
				NULL );

			if (STATUS_SUCCESS == status) {

				*SafeToOpen = ((PSCANNER_REPLY) notification)->SafeToOpen;

			} else {

				//
				//  Couldn't send message
				//

				DbgPrint( "!!! protegedados.sys --- ScannerUserMode nao conseguiu enviar mensagem para userspace, status 0x%X\n", status );
			}
		}

	} finally {

		if (NULL != buffer) {

			FltFreePoolAlignedWithTag( Instance, buffer, 'nacS' );
		}

		if (NULL != notification) {

			ExFreePoolWithTag( notification, 'nacS' );
		}

		if (NULL != volume) {

			FltObjectDereference( volume );
		}
	}

	return status;
}

