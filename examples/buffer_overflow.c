// Example 1: Buffer Overflow Vulnerability (CWE-119)
// This code is vulnerable to buffer overflow attacks

#include <stdio.h>
#include <string.h>

void vulnerable_function(char *user_input) {
    char buffer[64];
    
    // VULNERABLE: No bounds checking!
    // Attacker can overflow buffer with input > 64 bytes
    strcpy(buffer, user_input);
    
    printf("Buffer contains: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    // Directly passing user input without validation
    vulnerable_function(argv[1]);
    
    return 0;
}

/*
EXPLOIT SCENARIO:
If attacker provides input > 64 bytes:
- Buffer overflow occurs
- Can overwrite return address on stack
- Leads to Remote Code Execution (RCE)

REAL-WORLD EXAMPLE: Similar to WannaCry exploit (CVE-2017-0144)
*/
