#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
    int fd = open("/home/hacker/KernelSecurity/Level12.0/output.txt", O_WRONLY | O_APPEND | O_CREAT, 0644);
    for (int i = 1; i < argc; i++) {
      write(fd, argv[i], strlen(argv[i]));
      write(fd, "\n", 1);
    }
    close(fd);
    return 0;
}