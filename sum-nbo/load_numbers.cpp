#include<stdio.h>
#include<stdint.h>
#include<netinet/in.h>
#include "load_numbers.h"

int load_numbers(int i, FILE *filepointer, uint32_t *number){
	uint32_t box;
		
	if(fseek(filepointer, 0, SEEK_END) != 0) {printf("File%d seeking error\n", i); return 0;}

        long file_size = ftell(filepointer);
	if(file_size  == -1) {printf("File%d telling error\n", i); return 0;}
        
	rewind(filepointer);

        if(file_size<4) {printf("File%d is smaller than 4byte\n", i); return 0;}
        if(file_size>4) {printf("File%d is bigger than 4byte\n", i); return 0;}

	if(fread(&box, 4, 1, filepointer) == 0) {printf("File%d reading error\n", i); return 0;}
	*number = ntohl(box);

	return 1;
}
