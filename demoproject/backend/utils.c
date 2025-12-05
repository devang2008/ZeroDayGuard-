// VULNERABILITY: Buffer Overflow in C extension (CWE-119, CWE-120)

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// VULNERABILITY: Buffer overflow in string copy
void unsafe_copy(char* user_input) {
    char buffer[100];
    
    // DANGEROUS: No bounds checking!
    strcpy(buffer, user_input);
    
    printf("Copied: %s\n", buffer);
}

// VULNERABILITY: Format string vulnerability
void print_user_data(char* data) {
    // DANGEROUS: User input as format string
    printf(data);
}

// VULNERABILITY: NULL pointer dereference (CWE-476)
typedef struct {
    char* name;
    int age;
} User;

void process_user(User* user) {
    // VULNERABILITY: No NULL check!
    printf("User: %s, Age: %d\n", user->name, user->age);
}

// VULNERABILITY: Use after free (CWE-416)
void process_data() {
    char* data = (char*)malloc(100);
    strcpy(data, "Important data");
    
    free(data);
    
    // DANGEROUS: Using freed memory
    printf("Data: %s\n", data);
}

// VULNERABILITY: Integer overflow
int calculate_buffer_size(int count, int item_size) {
    // DANGEROUS: No overflow check
    return count * item_size;
}

// VULNERABILITY: Command injection through system()
void execute_command(char* filename) {
    char command[256];
    
    // DANGEROUS: Building command with user input
    sprintf(command, "cat %s", filename);
    system(command);
}

// VULNERABILITY: Race condition
FILE* global_file = NULL;

void write_to_file(char* data) {
    global_file = fopen("output.txt", "w");
    
    // Race condition: File might be closed by another thread
    fprintf(global_file, "%s", data);
    
    fclose(global_file);
}

int main() {
    printf("C Extension Module - INTENTIONALLY VULNERABLE\n");
    printf("DO NOT USE IN PRODUCTION!\n");
    
    return 0;
}
