
#include <stdio.h>
#include <string.h>
void foo(char* input){
	char name[10]={0};
	strcpy(name,input);
	//printf("%s\n",name);
}

int main(int argc, char* argv[]){
	int i = 0;
	printf("running...\n");
	if(argc < 1){
		printf("wrong\n");
	}	
	//char buf[25];
	//strcpy(buf,argv[1]);	
	foo(argv[1]);
	for(i = 1; i < 10; ++i)
		printf("ss\n");
	return 0;
}
