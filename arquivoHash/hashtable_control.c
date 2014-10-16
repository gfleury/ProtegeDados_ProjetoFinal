#include <windows.h>
#include <time.h>
#include "arquivoHash.h"


int _cdecl load_hashtable (PSCANNER_THREAD_CONTEXT Context, load_type type) {

	HANDLE policy_file = CreateFile (L"protegeDados.dat", GENERIC_READ, (FILE_SHARE_WRITE | FILE_SHARE_DELETE), NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dw_bytes_read;
	hash_list hash_entry;
	Context->id = 0;
	Context->local_version = 0;
	Context->flags = NO_FLAGS;

	if (!policy_file)
		return -1;

	if (!ReadFile(policy_file, (LPVOID)&Context->id, sizeof (Context->id), &dw_bytes_read, NULL))
		return -2;

	if (!ReadFile(policy_file, (LPVOID)&Context->local_version, sizeof (Context->local_version), &dw_bytes_read, NULL))
		return -2;

	if (!ReadFile(policy_file, (LPVOID)&Context->flags, sizeof (Context->flags), &dw_bytes_read, NULL))
		return -2;

	if (type == HEADERS) 
		goto cleanup;

	// Load infos and hashes
	while(ReadFile(policy_file, (LPVOID)&hash_entry, sizeof (hash_list), &dw_bytes_read, NULL) && dw_bytes_read != 0) {
		hash_table_add(Context->md5_table, &hash_entry.hash_info.hash_name, 16*sizeof(md5_byte_t), &hash_entry, sizeof(hash_list));
    }

cleanup:

	CloseHandle (policy_file);

	return TRUE;

}

typedef struct hash_write_callback_data {
	HANDLE policy_file;	
} hash_write_callback_data, *hash_write_callback_datap;

int iterate_write_hashtable (void *user, void *value, void *key, size_t key_len) {
	hash_write_callback_datap callback_data = (hash_write_callback_datap)user;
	hash_list hash_entry;
	DWORD dw_bytes_read;
		
	memcpy (&hash_entry, value, sizeof(hash_list));
	//memcpy (&hash_entry.id, key, sizeof(unsigned char));

	//printf ("ID=%d\n", hash_entry.id);

	WriteFile(callback_data->policy_file, (LPVOID)&hash_entry, sizeof (hash_list), &dw_bytes_read, NULL);

	//printf ("Size=%d %d\n", sizeof (hash_list), dw_bytes_read);

	return FALSE;
}

int iterate_list_hashtable (void *user, void *value, void *key, size_t key_len) {
	//enum tipo *tipo = (enum tipo*)user;
	hash_write_callback_datap callback_data = (hash_write_callback_datap)user;
	hash_list *hl;

	int i;
		
	hl = (hash_list *)value;	
	printf ("\tId: %d Nome: ", hl->id);
		
	for ( i=0; i < 16; i++) {
		printf ("0x%02x, ", hl->hash_info.hash_name[i]);
	}
	
	printf ("\n\t\t Informacao: ");

	for ( i=0; i < 16; i++) {
		printf ("0x%02x, ", hl->hash_info.hash_arquivo[i]);
	}

	
	for (i=0; i < 32 && hl->hash_info.acesso_livre_ids[i]; i++) {
		printf ("\n\t\t IDs que confiaveis: %d", hl->hash_info.acesso_livre_ids[i]);
	}

	printf ("\n");

	return FALSE;
}

int _cdecl save_hashtable (PSCANNER_THREAD_CONTEXT Context) {

	HANDLE policy_file = CreateFile (L"protegeDados.dat", GENERIC_WRITE, (FILE_SHARE_READ | FILE_SHARE_DELETE), NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dw_bytes_read;
	hash_write_callback_data call_backdata;

	if (!policy_file)
		return -1;

	if (!WriteFile(policy_file, (LPVOID)&Context->id, sizeof (Context->id), &dw_bytes_read, NULL)) 
		return -2;

	if (!WriteFile(policy_file, (LPVOID)&Context->local_version, sizeof (Context->local_version), &dw_bytes_read, NULL)) 
		return -2;

	if (!WriteFile(policy_file, (LPVOID)&Context->flags, sizeof (Context->flags), &dw_bytes_read, NULL))
		return -2;

	call_backdata.policy_file = policy_file;

	// dump md5 hashtable
	if (Context->md5_table) {
		hash_table_iterate (Context->md5_table, &iterate_write_hashtable, &call_backdata);
	}
	
	CloseHandle (policy_file);

	return TRUE;
}

int _cdecl command_line_control (int argc, char *argv[]) {
	SCANNER_THREAD_CONTEXT Context;
	Context.md5_table = hash_table_new(MODE_COPY);
	
	if (argc > 1) {
		if (load_hashtable (&Context, FULL) != 1) {
			printf ("Impossivel carregar arquivo de politicas.\n");
			goto cleanup;
		}

		if (!_strnicmp (argv[1], "listar", 6)) {
			hash_write_callback_data callback_data;
			
			printf ("\nID da politica: %d\n", Context.id);
			printf ("Local version   : %d\n", Context.local_version);
		/*	printf ("Politica de bloqueio USB: ");
			if ((Context.flags & BLOCK_USB_EXE) == BLOCK_USB_EXE)
				printf ("executaveis ");
			if ((Context.flags & BLOCK_USB_WRITE) == BLOCK_USB_WRITE)
				printf ("escrita ");
			if ((Context.flags & BLOCK_USB_USE) == BLOCK_USB_USE)
				printf ("bloqueado");
				*/
			printf ("\n");
			printf ("Hashes md5 adicionados: \n");
			hash_table_iterate (Context.md5_table, &iterate_list_hashtable, &callback_data);

			goto cleanup;
		}

		if (argc >= 4 && !_strnicmp (argv[1], "incluir", 7)) {
			if (!_strnicmp (argv[2], "hash", 4)) {
				static md5_byte_t *md5_hash = { 0 };
				static md5_byte_t *md5_name_hash = { 0 };
				hash_list hi;
				wchar_t *wc = NULL;

				size_t tmppath_size;
				size_t tmpwchar_size = 0;

				md5_hash = make_local_hashes (argv[3]);
				memcpy (hi.hash_info.hash_arquivo, md5_hash, 16*sizeof(md5_byte_t));

				tmppath_size =  MultiByteToWideChar(CP_ACP, 0, argv[3], -1, NULL, 0);
				
				wc = (wchar_t *) malloc (tmppath_size * sizeof(wchar_t));

				if (wc != NULL) {
					wchar_t physPath[1024] = { 0 };
					wchar_t finalPath[MAX_PATH];
					wchar_t logicalPath[4] = { 0 };
					int pathSize;

					/* convert from cp_string to wide_string */
					MultiByteToWideChar(CP_ACP, 0, argv[3], -1, wc, tmppath_size);

					swprintf(logicalPath, 3, L"%lc%lc", *wc, *(wc+1));
					pathSize = QueryDosDevice (logicalPath, physPath, 1024);

					physPath[pathSize+1] = '\0';

					pathSize = wcslen (physPath) + wcslen(wc);
					
					swprintf(finalPath, pathSize, L"%ls%ls", physPath, (wc+2));

				
					if (tmpwchar_size == 0)
						*wc = L'\0';
						
					_wcslwr_s(finalPath,  wcslen(finalPath) + 1);

					printf ("#%s#\n#%ls#\n#%ls#\n", argv[3], wc, finalPath);

					md5_name_hash = make_name_hashes(finalPath);
					memcpy (hi.hash_info.hash_name, md5_name_hash, 16*sizeof(md5_byte_t));

					free (wc);
				}
			
				if (!md5_hash) {
					printf ("Impossivel abrir arquivo para gerar hash.\n");
					goto cleanup;
				} else if (md5_name_hash != NULL && hash_table_lookup(Context.md5_table, md5_name_hash, 16*sizeof(md5_byte_t))) {
					printf ("Arquivo ja tem um hash proprio adicionado, se quiser altera-lo use a opcao alterar.\n");
					goto cleanup;
				}
				
				hi.id = Context.local_version + 1;

				if (argc >= 5) {
					int count = 0;
					for (; count < (argc - 4); count++) {
						hi.hash_info.acesso_livre_ids[count] = atoi(argv[count + 4]);
						printf ("str = %s, int = %d\n", argv[count + 4], atoi(argv[count + 4]));
					}	
					memset((hi.hash_info.acesso_livre_ids + (argc - 4)), 0, 32 - (argc - 4));
				} else {
					memset(hi.hash_info.acesso_livre_ids, 0, 32);
				}

				hash_table_add(Context.md5_table, md5_name_hash, 16*sizeof(md5_byte_t), &hi, sizeof(hash_info));
				printf ("Hash adicionado nas politicas.\n");
				if (hash_table_lookup(Context.md5_table, md5_name_hash, 16*sizeof(md5_byte_t)))
					printf ("Hash adicionado e encontrado atrav'es de pesquisa.\n");

				printf ("Id=%d\n", hi.id);
			} 

			Context.local_version++; // Aumenta o valor da versao local, para informar que houve mudanca
			save_hashtable (&Context);
		}
    }

cleanup:

	hash_table_delete (Context.md5_table);


	return 1;
}