/***
Program Written By Hasitha Dias
Student ID: 789929
University/GitLab Username: diasi
Email: i.dias1@student.unimelb.edu.au
Last Modified Date: 20/05/2018
***/

#ifndef CERTCHECK_H
#define CERTCHECK_H

#include <stdio.h>
#include <string.h>
#include "malloc.h"
#include <time.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>


struct node {
    char* certificate;
    char* url;
    int valid;
    struct node *next;
};
typedef struct node NODE;

#define FILENAME_TO_WRITE "babe.csv"
#define TERMINATION_CHARACTER '\0'
#define TWO_CHARACTERS 2
#define CHARACTER_STAR "*"
#define BUFFER_SIZE 1024
#define COMMA ","
#define EOL "\n"
#define BITS_IN_BYTE 8
#define MAX_BITS 2048

NODE* read_CSVfile(NODE *head, const char* filename);
int check(char* certificate, char* url);
X509* read_certificate(X509 *cert, char* certificate);
int validate_date(X509 *cert);
int validate_CN(const char *hostname, const X509 *server_cert);
int validate_SAN(const char *hostname, const X509 *server_cert);
int check_wildcards(const char* hostname, char* dns);
int validate_RSA_key_length(X509 *cert);
int validate_basic_constraints(X509 *cert);
int validate_extended_key_usage(X509 *cert);
void write_to_file(NODE *data);
void free_data(NODE *head);


#endif
