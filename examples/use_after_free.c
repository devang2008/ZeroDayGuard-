// Example 5: Use After Free (CWE-416)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char *data;
} Buffer;

Buffer *create_buffer(const char *str) {
    Buffer *buf = (Buffer*)malloc(sizeof(Buffer));
    buf->data = strdup(str);
    return buf;
}

void free_buffer(Buffer *buf) {
    if (buf) {
        free(buf->data);
        free(buf);
    }
}

int main() {
    Buffer *buf = create_buffer("sensitive data");
    
    // Free the buffer
    free_buffer(buf);
    
    // VULNERABLE: Use after free!
    // Buffer already freed but still accessed
    printf("Data: %s\n", buf->data);  // CRASH or exploit
    
    return 0;
}

/*
EXPLOIT SCENARIO:
- Memory freed but pointer still used
- Can lead to arbitrary code execution
- Attacker can control freed memory contents

REAL-WORLD: Critical vulnerability in browsers, kernels
FIX: Set pointer to NULL after free
*/
