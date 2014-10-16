#include <windows.h>
#include <stdio.h>
#include <WinIoCtl.h>

// compile this as cpp use /TP in sources

int PrintResult(LPWSTR FunctionName,LPWSTR AdditionalMessage) {

	LPVOID lpMsgBuf;
#ifdef BUGGY
	FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &lpMsgBuf, 0, NULL);
	wprintf(L"Function %ws Returned\n%ws%ws\n\n", FunctionName, (LPWSTR)lpMsgBuf, AdditionalMessage);
	LocalFree( lpMsgBuf );
#endif
	return 1;
}


int _cdecl install_minifilter (void) {

	HRESULT            hr;
	HKEY            phkey;
	HKEY        insthkey;
	HKEY        instcdohkey;
	DWORD            lpdwDisposition = 0;
	LPWSTR		ServiceDescription = L"protegeDados minifilter scanner";
	LPWSTR    InstancesKey = L"Miniscan";
	LPWSTR Altitude = L"265000";
	ULONG    DebugLevel =    0xffffffff;
	ULONG    Flags = 0x0;

	SC_HANDLE  hSCManager;

	if( (RegCreateKeyExW(                   
		HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Services\\protegeDados",
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,NULL,
		&phkey,
		&lpdwDisposition
		))!= ERROR_SUCCESS)    {
			PrintResult(L"RegCreateKeyEx",L"New SubKey Miniscan Not Created");
			return 0;
	}

	switch(lpdwDisposition) {

	case 1:

		PrintResult(L"RegCreateKeyEx",L"New SubKey Miniscan Created");

		break;

	case 2:

		PrintResult(L"RegCreateKeyEx",L"Old SubKey Miniscan Opened");

		break;

	default:

		break;

	}


	if( (RegSetValueExW(
		phkey,
		L"Description",
		0,
		REG_SZ,
		(CONST BYTE *)ServiceDescription,
		((wcslen(ServiceDescription) * sizeof(WCHAR)) + sizeof(WCHAR))  // size including NULL TERMINATOR
		)) != ERROR_SUCCESS) {

			PrintResult(L"RegSetValueEx",L"Service Description Value Not Set");

			RegCloseKey(phkey);

			return 0;
	}

	PrintResult(L"RegSetValueEx",L"Service Description Value Set");


	if ( (RegSetValueExW(
		phkey,
		L"DebugLevel",
		0,
		REG_DWORD,
		(CONST BYTE *)&DebugLevel,
		sizeof(DebugLevel)
		))!= ERROR_SUCCESS) {

			PrintResult(L"RegSetValueEx",L"DebugLevel  Value Not Set");

			RegCloseKey(phkey);

			return 0;
	}

	PrintResult(L"RegSetValueEx",L"DebugLevel  Value Set");


	lpdwDisposition = 0;

	

	if ( (RegCreateKeyExW(
		phkey,
		L"Instances",
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		NULL,
		&insthkey,
		&lpdwDisposition
		))!= ERROR_SUCCESS) {

			PrintResult(L"RegCreateKeyEx",L"New SubKey Instances Not Created");

			RegCloseKey(phkey);

			return 0;
	}

	switch(lpdwDisposition) {

	case 1:

		PrintResult(L"RegCreateKeyEx",L"New SubKey Instances Created");

		break;

	case 2:

		PrintResult(L"RegCreateKeyEx",L"Old SubKey Instances Opened");

		break;

	default:

		break;

	}

	

	if ( (RegSetValueExW(
		insthkey,
		L"DefaultInstance",
		0,
		REG_SZ,
		(CONST BYTE *)InstancesKey,
		((wcslen(InstancesKey) * sizeof(WCHAR)) + sizeof(WCHAR)) // size including NULL TERMINATOR
		))!= ERROR_SUCCESS) {

			PrintResult(L"RegSetValueEx", L"DefaultInstance  Value Not Set");

			RegCloseKey(phkey);

			RegCloseKey(insthkey);

			return 0;
	}

	PrintResult(L"RegSetValueEx", L"DefaultInstance  Value Set");

	lpdwDisposition = 0;

	if ( (RegCreateKeyExW(
		phkey,
		L"Instances\\Miniscan",
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS,
		NULL,
		&instcdohkey,
		&lpdwDisposition
		))!= ERROR_SUCCESS) {

			PrintResult(L"RegCreateKeyEx", L"New SubKey Instances\\Miniscan Not Created");

			RegCloseKey(phkey);

			RegCloseKey(insthkey);

			return 0;
	}
	switch(lpdwDisposition) {

	case 1:

		PrintResult(L"RegCreateKeyEx", L"New SubKey Instances\\Miniscan Created");

		break;

	case 2:

		PrintResult(L"RegCreateKeyEx", L"Old SubKey Instances\\Miniscan Opened");

		break;

	default:

		break;

	}

	

	if ( (RegSetValueExW(
		instcdohkey,
		L"Altitude",
		0,
		REG_SZ,
		(CONST BYTE *)Altitude,
		((wcslen(Altitude) * sizeof(WCHAR)) + sizeof(WCHAR)) // size including NULL TERMINATOR
		))!= ERROR_SUCCESS ) {

			PrintResult (L"RegSetValueEx", L"Altitude  Value Not Set");

			RegCloseKey (phkey);

			RegCloseKey (insthkey);

			RegCloseKey (instcdohkey);

			return 0;
	}

	PrintResult (L"RegSetValueEx", L"Altitude  Value Set");



	if ( ( RegSetValueExW(
		instcdohkey,
		L"Flags",
		0,
		REG_DWORD,
		(CONST BYTE *)&Flags,
		sizeof(Flags)
		))!= ERROR_SUCCESS ) {

			PrintResult(L"RegSetValueEx",L"Flags  Value Not Set");

			RegCloseKey(phkey);

			RegCloseKey(insthkey);

			RegCloseKey(instcdohkey);

			return 0;
	}


	RegCloseKey(phkey);

	RegCloseKey(insthkey);

	RegCloseKey(instcdohkey);

	PrintResult(L"RegSetValueEx",L"Flags  Value Set");



	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	PrintResult(L"OpenSCManager", L"Opening Service Control Manager Succeded");


	if(hSCManager) {
		SC_HANDLE    hService;
		DWORD        tagid;


		hService = CreateServiceW (
			hSCManager,
			L"protegeDados",
			L"protegeDados",
			SERVICE_START | DELETE | SERVICE_STOP,
			SERVICE_FILE_SYSTEM_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
			L"system32\\drivers\\protegeDados.sys",
			L"FSFilter Activity Monitor",
			&tagid,
			L"FltMgr",
			NULL,
			NULL
			);

		if(!hService) {

			hService = OpenServiceW(
				hSCManager,
				L"protegeDados",
				SERVICE_START | DELETE | SERVICE_STOP
				);
		}

		if(hService) {

			PrintResult(L"CreateService",L"Created Service Successfully\nStarting Service");

			StartService(
				hService,
				0,
				NULL
				);

			PrintResult(L"StartService", L"Service Started Successfully\n");

			CloseServiceHandle(hService);

		}

		CloseServiceHandle(hSCManager);

	}

	return 0;
}

int _cdecl uninstall_minifilter (void) {

	SC_HANDLE  hService = NULL;
	SC_HANDLE  hSCManager = NULL;
	int ret = 0;

	hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	PrintResult(L"OpenSCManager", L"Opening Service Control Manager Succeded");

	if(hSCManager) {
		if(!hService) {
			SERVICE_STATUS    ss;

			hService = OpenServiceW(hSCManager, L"protegeDados", SERVICE_START | DELETE | SERVICE_STOP);

			ControlService(hService, SERVICE_CONTROL_STOP, &ss);
			DeleteService(hService);
			ret = 1;
		}
		CloseServiceHandle(hSCManager);
	}
	return ret;
}