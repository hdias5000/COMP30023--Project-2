/***
Program Written By Hasitha Dias
Student ID: 789929
University/GitLab Username: diasi
Email: i.dias1@student.unimelb.edu.au
Last Modified Date: 24/05/2018
***/

/////This is the Header for certcheck.c

#ifndef CERTCHECK_H
#define CERTCHECK_H

#include <stdio.h>
#include <string.h>
#include "malloc.h"
#include "assert.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

/*This structure stores all the information from the CSV file as a linked
list(a node for each certificate,domain).*/
struct node {
    char* certificate;
    char* url;
    int valid;
    struct node *next;
};
typedef struct node NODE;

#define FILENAME_TO_WRITE "output.csv"      //final output filename
#define TERMINATION_CHARACTER '\0'
#define TWO_CHARACTERS 2                    //used for wildcards
#define CHARACTER_STAR "*"                  //used to check for wildcards
#define BUFFER_SIZE 1024                    //size to store from CSV file
#define COMMA ","
#define EOL "\n"
#define BITS_IN_BYTE 8                      //converts bytes->bits (RSA)
#define MAX_BITS 2048                       //mac no. of bits for RSA key

/*This function is used to read the CSV file in to a linked list.*/
NODE* read_CSVfile(NODE *head, const char* filename);

/*This function calls all the functions required to read the certificate and
to validate it.*/
int check(char* certificate, char* url);

/*This function reads each certificate filename as a X509 certificate.*/
X509* read_certificate(X509 *cert, char* certificate);

/*This function checks if the current date is within the NotBefore and NotAfter
date of the certificate.*/
int validate_date(X509 *cert);

/*Checks if given Domain Name from CSV file is same as the Common Name given in
the certificate(also checks for wildcards).*/
int validate_CN(const char *hostname, const X509 *server_cert);

/*Checks if given Domain Name from CSV file is same as any of the Alternative
Subject Names(Common Name) given in the certificate(checks for wildcards).*/
int validate_SAN(const char *hostname, const X509 *server_cert);

/*When given the hostname and wildcard, checks if the hostname is similar.*/
int check_wildcards(const char* hostname, char* dns);

/*This function checks if the RSA key length is greater than or atleast equal
to 2048 bits.*/
int validate_RSA_key_length(X509 *cert);

/*This function checks if the CA flag of the basic constrainsts is false.*/
int validate_basic_constraints(X509 *cert);

/*This function checks if Extended Key Usage includes TLS Server
Authentication.*/
int validate_extended_key_usage(X509 *cert);

/*This function writes data from a linked list into a CSV file.*/
void write_to_file(NODE *data);

/*Frees all the data from the linked list.*/
void free_data(NODE *head);


#endif
