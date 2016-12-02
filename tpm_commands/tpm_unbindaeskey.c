#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv) {
    int     i, exitCode = -1;
    char    *input_file = NULL, *key_name = NULL, *output_file = NULL, *key_auth;
    char	command0[2304]={0};

    printf("Parsing arguments to identify tpm command and required parameters");
    for (i = 0; i < argc; i++) {
        if ( argv[i] && strcmp(argv[i], "-i") == 0 ) {
            input_file = argv[i+1];
            printf("input_file : %s\n", input_file);
        }
        if ( argv[i] && strcmp(argv[i], "-k") == 0 ) {
            key_name = argv[i+1];
            printf("key_name : %s\n", key_name);
        }
        if ( argv[i] && strcmp(argv[i], "-o") == 0 ) {
            output_file = argv[i+1];
            printf("output_file : %s\n", output_file);
        }
		if ( argv[i] && strcmp(argv[i], "-q") == 0 ) {
            key_auth = argv[i+1];
            printf("key_auth : %s\n", key_auth);
        }
    }

	if(output_file != NULL)
		sprintf_s(command0,sizeof(command0),"TPMTool.exe decrypt %s %s %s > %s", key_name, input_file, key_auth, output_file);
	else
		sprintf_s(command0,sizeof(command0),"TPMTool.exe decrypt %s %s %s", key_name, input_file, key_auth);
	printf("Unbinding Command : %s\n", command0);

	i = system(command0);
	printf("system call to tpm_unbindaeskey command exit status : %d\n", i);
    if(i != 0)
		exitCode = -1;
    exitCode = 0;

    return exitCode;
}