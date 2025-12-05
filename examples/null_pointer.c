// Example 4: NULL Pointer Dereference (CWE-476)

#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int id;
    char name[64];
} User;

void process_user(User *user) {
    // VULNERABLE: No NULL check!
    // Crashes if user is NULL (Denial of Service)
    printf("User ID: %d\n", user->id);
    printf("User Name: %s\n", user->name);
}

int main() {
    User *user = (User*)malloc(sizeof(User));
    
    // Simulate allocation failure
    if (some_condition) {
        free(user);
        user = NULL;
    }
    
    // CRASH: Dereferencing NULL pointer
    process_user(user);
    
    return 0;
}

/*
EXPLOIT SCENARIO:
- Attacker triggers allocation failure
- NULL pointer dereference causes crash
- Leads to Denial of Service (DoS)

FIX: Add NULL check before dereferencing
*/
