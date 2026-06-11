#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h> 

int main(int argc, char *argv[]) {
	uint32_t numbers[10];
	uint8_t network_buffer[40];

	if(argc > 11) {printf("The maximum number of files that can be inserted is 10."); return 1;}
	if (argc < 2) {printf("File not found"); return 1;}
	
	for (int i = 1; i <argc; i++){
		FILE *fp = fopen(argv[i], "rb");

		if (fp == NULL) {
			printf("fopen (no.%d file): No such file or directoy",i);
			return 1;
		}

	//version1
	size_t file_size = 0;
	
	while (fread((network_buffer) + 4*(i-1) + file_size ,1,1,fp) == 1) {
		file_size ++;} // I will not implement fread checking. Implemented in version 2.

	if(file_size<4) {printf("File%d is smaller than 4byte", i); fclose(fp); return 1;}
	if(file_size>4) {printf("File%d is bigger than 4byte", i); fclose(fp); return 1;}
	
	fclose(fp);
	}

	

	for(int i = 0; i< 4 * (argc - 1); i++) {
		printf("%02x" , network_buffer[i]);
		if(i%4 == 3) printf("\n");
	}

	
	uint32_t *test = (uint32_t *)network_buffer;
	for(int i = 0; i < (argc -1); i++){
		printf("%u\n", ntohl(*(test+i)));}

	return 0;
	}

	

	/*version2
	if(fseek(filepointer, 0, SEEK_END) != 0) {printf("File%d seeking error", i); fclose(fp); return 0;}

	long file_size = ftell(filepointer);
	if(file_size == -1) {printf("File%d telling error", i); fclose(fp); return 0;}

        rewind(filepointer);


	if(file_size<4) {printf("File%d is smaller than 4byte", i); fclose(fp);  return 1;}
        if(file_size>4) {printf("File%d is bigger than 4byte", i); fclose(fp); return 1;}
	
	if(fread(numbers + i, 4, 1, fp) != 1) {printf("File%d reading failed", i); fclose(fp); return 1;}
	printf("before ntohl: %u(0x%08x)\n", numbers[i],numbers[i]);
	printf("after ntohl: %u(0x%08x)\n", ntohl(numbers[i]), ntohl(numbers[i]));
	fclose(fp); }

	return 0; } */
