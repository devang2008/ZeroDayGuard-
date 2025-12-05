// CWE-89: SQL Injection Vulnerability
#include <stdio.h>
#include <string.h>
#include <mysql/mysql.h>

void login_user(char* username, char* password) {
    MYSQL *conn;
    char query[256];
    
    // VULNERABLE: SQL injection via string concatenation
    sprintf(query, "SELECT * FROM users WHERE username='%s' AND password='%s'", 
            username, password);
    
    // An attacker could input: admin' OR '1'='1
    // Query becomes: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='...'
    
    mysql_query(conn, query);
    
    printf("Login attempt for: %s\n", username);
}

void search_products(char* search_term) {
    MYSQL *conn;
    char sql[512];
    
    // VULNERABLE: User input directly concatenated
    strcpy(sql, "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'");
    
    mysql_query(conn, sql);
}

int main() {
    char user_input[100];
    char pwd[100];
    
    printf("Username: ");
    scanf("%s", user_input);
    
    printf("Password: ");
    scanf("%s", pwd);
    
    login_user(user_input, pwd);
    
    return 0;
}
