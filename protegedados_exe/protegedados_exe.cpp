#include "arquivoHash.h"
#include <string.h>

int main (int argc, char *argv[]) {
	int threads = SCANNER_DEFAULT_THREAD_COUNT;
	int request = SCANNER_DEFAULT_REQUEST_COUNT;
	int never_stop = 0;

	if (argc > 1) {
		/*wchar_t a[] = L"\\device\\harddiskvolume1\\windows\\system32\\cmd.exe";//temp\\udd28c9.tmp";
		wchar_t b[] = L"\\device\\harddiskvolume1\\windows\\system32\\cmd.exe";
		md5_byte_t name_digest[16];
		md5_byte_t name_digestb[16];
		int opt;
		calcula_hash_md5_path (a, sizeof(a), name_digest);
		printf ("Size=%d wcslen=%d\n", wcslen(a), sizeof(a));
		for (opt=0; opt < 16; opt++) {
				printf ("%02x, ", name_digest[opt]);
			}

			calcula_hash_md5_path (b, sizeof(b), name_digestb);
		printf ("\n");
		for (opt=0; opt < 16; opt++) {
				printf ("%02x, ",name_digestb[opt]);
			}

			
		printf ("\n");
		*/
		return command_line_control (argc, argv);
	}

	install_minifilter();

	// Inicia Threads para leitura das MSGs enviadas do KernelSpace
	executaProtegeDados (threads, request, &never_stop);
		
	uninstall_minifilter();

}