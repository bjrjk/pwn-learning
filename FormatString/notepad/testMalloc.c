#include <stdio.h>
#include <stdlib.h>
int main(){
	for(int i=0; i<10; i++){
		void *p = malloc(0x20);
		printf("%p\n", p);
	}
	return 0;
}
