#include <stdio.h>
#include <string.h>
#include <unistd.h>
void SayHello(void){
    char tmpName[60];
    read(0, tmpName, 1000);
    printf("Hello %s\n", tmpName);
}

int main(int argc, char** argv){
    SayHello();
    return 0;
}
