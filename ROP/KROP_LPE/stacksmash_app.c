#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define DEVICE_NAME "/dev/stacksmash_device"

int main(int argc, char **argv) {
    int ret, fd, read_length;
    read_length = atoi(argv[2]);
    char *message = malloc(sizeof(char) * read_length);

    if (argc < 2) {
        printf("Usage: %s [message to write] [read length]\n", argv[0]);
        return -1;
    }
    fd = open(DEVICE_NAME, O_RDWR);
    if (fd < 0) {
        printf("[stacksmash_driver main] Failed to open device [%s]\n", DEVICE_NAME);
        return -1;
    }
    ret = write(fd, argv[1], strlen(argv[1]));
    if (ret < 0) {
        printf("[stacksmash_driver main] Failed to write to device [%s]\n", DEVICE_NAME);
        return -1;
    }
    ret = read(fd, message, read_length);
    if (ret < 0) {
        printf("[stacksmash_driver main] reading from the device [%s]\n", DEVICE_NAME);
        return -1;
    }
    printf("[stacksmash_driver] read message from device ['%s']\n", message);
    return 0;
}
