#include <stdio.h>
#include <string.h>

void badFunc(){
	int i = 0;
	while(i < 100000) ++i;
	return ;
}

void test(){
	printf("aaaaa\n");
}

int main(int argc, char *argv[]){
	if(argc != 3) {
		badFunc();
		printf("bad address1:%p\n");
		return 1;
	}
	char *password = "Totally not the password...";
	if(strcmp(password, argv[1]) != 0){
		badFunc();
		printf("bad address2:%p\n");
		return 1;
	}
	printf("right printf %s at %p\n",argv[2]);
	test();
	return 0;
}