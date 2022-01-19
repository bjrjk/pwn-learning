#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void pwnable();
void init();
__attribute__((aligned(0x100)))
void flag(){
    asm volatile(".byte 0x90");
    asm volatile(".byte 0x90");
    asm volatile(".byte 0x90");
    asm volatile(".byte 0x90");
    asm volatile(".byte 0x90");
    asm volatile(".byte 0x90");
    asm volatile(".byte 0x90");
    asm volatile(".byte 0x90");
    asm volatile(".byte 0x90");
    asm volatile(".byte 0x90");
    system("cat flag");
    write(1, "Unbelieveable! You must be an experienced hacker!!\n", 51);
    write(1, "That's your reward!!", 20);
}
int main(){
    init();
    write(1, "You are so lucky to have unlimited chance!!! xm!!!\n", 51);
    while(1){
        pwnable();
    }
}
void init(){
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
}
void pwnable(){
    char buf[0x10];
    write(1, "> ", 2);
    read(0, buf, 0x29);
    write(1, "Let's check if you are successful. \n", 36);
    puts(buf);
    buf[0x18] = 0x00;
}
