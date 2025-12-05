// CWE-22: Path Traversal Vulnerability
#include <stdio.h>
#include <string.h>

void read_user_file(char* filename) {
    FILE* fp;
    char path[256];
    char buffer[1024];
    
    // VULNERABLE: No validation of filename
    sprintf(path, "/var/www/uploads/%s", filename);
    
    // Attacker can input: ../../../etc/passwd
    // Path becomes: /var/www/uploads/../../../etc/passwd → /etc/passwd
    
    fp = fopen(path, "r");
    if (fp) {
        fread(buffer, 1, sizeof(buffer), fp);
        printf("File contents: %s\n", buffer);
        fclose(fp);
    }
}

void download_file(char* user_supplied_path) {
    FILE* fp;
    
    // VULNERABLE: Direct use of user input
    fp = fopen(user_supplied_path, "r");
    
    // Can access ANY file on the system!
}

// SAFE VERSION: Validate path
void read_user_file_safe(char* filename) {
    FILE* fp;
    char path[256];
    char real_path[256];
    
    // Remove ../ sequences
    if (strstr(filename, "../") || strstr(filename, "..\\")) {
        printf("Invalid filename\n");
        return;
    }
    
    sprintf(path, "/var/www/uploads/%s", filename);
    
    // Resolve to real path
    realpath(path, real_path);
    
    // Verify it's still in allowed directory
    if (strncmp(real_path, "/var/www/uploads/", 17) != 0) {
        printf("Access denied\n");
        return;
    }
    
    fp = fopen(real_path, "r");
    // ... rest of code
}

int main() {
    char filename[100];
    
    printf("Enter filename: ");
    scanf("%s", filename);
    
    read_user_file(filename);  // VULNERABLE
    
    return 0;
}
