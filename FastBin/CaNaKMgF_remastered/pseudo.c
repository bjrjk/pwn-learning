char* alloc_list[100];
unsigned int alloc_idx = 0;
int main() {
  unsigned int option, size, index;
  while (1) {
    scanf("%u", &option);
    switch (option) {
      case 1: { // allocate(size, data)
        scanf("%u", &size);
        char *buf = malloc(size);
        read(0, buf, size);
        alloc_list[alloc_idx++] = buf;
        break;
      }
      case 3: { // free(index)
        scanf("%u", &index);
        free(alloc_list[index]);
        // alloc_list[index] is a 
        // dangling pointer now
        break;
      }
      case 4: { // read(index)
        scanf("%u", &index);
        puts(alloc_list[index]);
        break;
      }
    }
  }
}

