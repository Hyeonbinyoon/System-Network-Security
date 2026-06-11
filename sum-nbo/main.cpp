#include <stdio.h>
#include <stdint.h>
#include "load_numbers.h"

int main(int argc, char*argv[]){
	uint32_t numbers[100];
	uint32_t result = 0;
	if(argc > 101) {printf("The maximum number of files that can be inserted is 100.\n"); return 1;}
        if (argc < 2) {printf("File not found\n"); return 1;}

	for (int i = 1; i <argc; i++){
                FILE *fp = fopen(argv[i], "rb");

                if (fp == NULL) {
                        printf("fopen (no.%d file): No such file or directoy\n",i);
                        return 1;
                }

		if(load_numbers(i, fp, numbers + (i-1)) == 0) {fclose(fp); return 1;}
		
		fclose(fp);
	}


	for(int i = 0; i < (argc -1); i++){
		result += numbers[i];
	}


	for(int i = 0; i < (argc - 1); i++){
		if(i == 0) printf("%u(0x%08x) ", numbers[i], numbers[i]);
		else printf("+ %u(0x%08x) ", numbers[i], numbers[i]);
	}

	printf("= %u(0x%08x)\n", result, result);



	return 0;
}

