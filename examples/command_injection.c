// Example 3: Command Injection Vulnerability (CWE-78)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void process_file(char *filename) {
    char command[256];
    
    // VULNERABLE: Command injection!
    // User can inject shell commands via filename
    sprintf(command, "cat %s", filename);
    
    // DANGEROUS: Executing user-controlled command
    system(command);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }
    
    process_file(argv[1]);
    
    return 0;
}

/*
EXPLOIT SCENARIO:
Attacker provides: "file.txt; rm -rf /"
Command becomes: "cat file.txt; rm -rf /"
Result: Deletes entire filesystem!

REAL-WORLD: Similar to Shellshock (CVE-2014-6271)
*/
