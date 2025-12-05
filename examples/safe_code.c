// Example 2: SAFE Code with Proper Bounds Checking

#include <stdio.h>
#include <string.h>

void safe_function(char *user_input) {
    char buffer[64];
    
    // SAFE: Using strncpy with bounds checking
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null termination
    
    printf("Buffer contains: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    // Input validation
    if (strlen(argv[1]) > 63) {
        fprintf(stderr, "Error: Input too long (max 63 characters)\n");
        return 1;
    }
    
    safe_function(argv[1]);
    
    return 0;
}

/*
SECURITY MEASURES:
1. strncpy() instead of strcpy() - prevents overflow
2. Explicit null termination
3. Input length validation
4. Error handling for invalid input

This code is SAFE from buffer overflow attacks.
*/
