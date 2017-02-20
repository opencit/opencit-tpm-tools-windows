#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <shlwapi.h>

int main(int argc, char** argv) {
    int     i, exitCode = -1;
    char    *input_file = NULL, *key_name = NULL, *output_file = NULL, *key_auth = NULL, *blob_file = NULL;
    char	command0[2304]={0};

    for (i = 0; i < argc; i++) {
        if ( argv[i] && strcmp(argv[i], "-i") == 0 ) {
            input_file = argv[i+1];
        }
        if ( argv[i] && strcmp(argv[i], "-k") == 0 ) {
            key_name = argv[i+1];
        }
        if ( argv[i] && strcmp(argv[i], "-o") == 0 ) {
            output_file = argv[i+1];
        }
		if ( argv[i] && strcmp(argv[i], "-q") == 0 ) {
            key_auth = argv[i+1];
        }
		if ( argv[i] && strcmp(argv[i], "-b") == 0 ) {
            blob_file = argv[i+1];
        }
    }

	char path[MAX_PATH];//always use MAX_PATH for filepaths
	char tpmtools[MAX_PATH];//always use MAX_PATH for filepaths
	GetModuleFileName(NULL,path,sizeof(path));
	PathRemoveFileSpec(path);
	sprintf_s(tpmtools,sizeof(tpmtools),"%s\\%s", path, "TPMTool.exe");

	output_file = (output_file == NULL) ? "" : output_file;
	sprintf_s(command0,sizeof(command0),"\"%s\" importaik %s %s", tpmtools, blob_file, key_name);
	i = system(command0);
	if ( i == 0 ) {
		sprintf_s(command0,sizeof(command0),"\"%s\" unbind %s %s %s %s", tpmtools, key_name, input_file, key_auth, output_file);
		i = system(command0);
		if ( i == 0 )
			exitCode = 0;
	}

    return exitCode;
}