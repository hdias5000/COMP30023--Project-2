/***
Program Written By Hasitha Dias
Student ID: 789929
University/GitLab Username: diasi
Email: i.dias1@student.unimelb.edu.au
Last Modified Date: 20/05/2018
***/

#include "certcheck.h"

void main(int argc, char const *argv[]) {
    NODE *head,*list;
    head = read_CSVfile(head, argv[1]);

    list = head;
    while (list){
        list->valid = check(list->certificate, list->url);
        printf("%s,%s,%d\n",list->certificate,list->url,list->valid );
        list = list->next;
    }

    write_to_file(head);
    free_data(head);
}

NODE* read_CSVfile(NODE *head, const char* filename){
    char buffer[BUFFER_SIZE], *record, *line;
    FILE *fstream = fopen(filename, "r");
    NODE *current, *new = 0;
    int count_nodes = 0;

    if(fstream == NULL){
        fprintf(stderr, "Error in reading CSV filename");
        exit(EXIT_FAILURE);
    }

    while((line=fgets(buffer,sizeof(buffer),fstream))!=NULL){
        new  = (NODE *)malloc(sizeof(NODE));

        record = strtok(line,COMMA);
        new->certificate = malloc(sizeof(record));
        strcpy(new->certificate, record) ;

        record = strtok(NULL,EOL);
        new->url = malloc(sizeof(record));
        strcpy(new->url, record);

        new->next = 0;
        if (count_nodes==0){
            head = current = new;
        }else{
            current->next = new;
            current = new;
        }
        count_nodes++;
    }
    return head;
}

int check(char* certificate, char* url){
    X509 *cert = NULL;
    int passed = 1;

    cert = read_certificate(cert,certificate);

    if (!validate_date(cert)){
        passed = 0;
    }else if (!validate_CN(url,cert) && !validate_SAN(url,cert)){
        passed = 0;
    }else if (!validate_RSA_key_length(cert)){
        passed = 0;
    }else if (!validate_basic_constraints(cert)){
        passed = 0;
    }else if (!validate_extended_key_usage(cert)){
        passed = 0;
    }

    X509_free(cert);
    return passed;
}

X509* read_certificate(X509 *cert, char* certificate){
    BIO *certificate_bio = NULL;
    X509_NAME *cert_issuer = NULL;
    X509_CINF *cert_inf = NULL;
    STACK_OF(X509_EXTENSION) * ext_list;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    certificate_bio = BIO_new(BIO_s_file());

    //Read certificate into BIO
    if (!(BIO_read_filename(certificate_bio, certificate))){
        fprintf(stderr, "Error in reading cert BIO filename");
        exit(EXIT_FAILURE);
    }

    if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL))){
        fprintf(stderr, "Error in loading certificate");
        exit(EXIT_FAILURE);
    }
    return cert;
    BIO_free_all(certificate_bio);
}

int validate_date(X509 *cert){
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    int sec,day,sec1,day1;

    ASN1_TIME_diff(&day, &sec, not_before,NULL);
    if ((day<0) || (sec<0)){
        return 0;
    }
    ASN1_TIME_diff(&day1, &sec1, NULL,not_after);
    if ((day1<0) || (sec1<0)){
        return 0;
    }
    return 1;
}

int validate_CN(const char *hostname, const X509 *server_cert) {
	int common_name_loc = -1;
	X509_NAME_ENTRY *common_name_entry = NULL;
	ASN1_STRING *common_name_asn1 = NULL;
	char *common_name_str = NULL;

	// Find the position of the CN field in the Subject field of the certificate
	common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name((X509 *) server_cert), NID_commonName, -1);
	if (common_name_loc < 0) {
        fprintf(stderr, "Error in finding position of CN");
		return 0;
	}

	// Extract the CN field
	common_name_entry = X509_NAME_get_entry(X509_get_subject_name((X509 *) server_cert), common_name_loc);
	if (common_name_entry == NULL) {
        fprintf(stderr, "Error in extracting CN");
		return 0;
	}

	// Convert the CN field to a C string
	common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
	if (common_name_asn1 == NULL) {
        fprintf(stderr, "Error in CN field to string");
		return 0;
	}
	common_name_str = (char *) ASN1_STRING_data(common_name_asn1);

    if (check_wildcards(hostname,common_name_str)) {
        return 1;
    }
    return 0;
}

int validate_SAN(const char *hostname, const X509 *server_cert) {
	int i;
	int san_names_nb = -1;
	STACK_OF(GENERAL_NAME) *san_names = NULL;

	// Try to extract the names within the SAN extension from the certificate
	san_names = X509_get_ext_d2i((X509 *) server_cert, NID_subject_alt_name, NULL, NULL);
	if (san_names == NULL) {
		fprintf(stderr, "Error in extracting SAN");
	}
	san_names_nb = sk_GENERAL_NAME_num(san_names);

	// Check each name within the extension
	for (i=0; i<san_names_nb; i++) {
		const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);
        char *dns_name = (char *) ASN1_STRING_data(current_name->d.dNSName);
        if (check_wildcards(hostname,dns_name)) {
            sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
            return 1;
        }
	}
	sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
	return 0;
}

int check_wildcards(const char* hostname, char* dns){
    int diff = 0;
    char firstletter[TWO_CHARACTERS];
    firstletter[0] = dns[0];
    firstletter[1]=TERMINATION_CHARACTER;

    if (strcmp(firstletter,CHARACTER_STAR)==0) {
        dns = dns+1;
        if (strlen(hostname)>strlen(dns)) {
            diff = strlen(hostname)-strlen(dns);
        }
    }
    if (strcasecmp(hostname+diff, dns) == 0) {
        return 1;
    }
    return 0;
}

int validate_RSA_key_length(X509 *cert){
    EVP_PKEY *public_key = X509_get_pubkey(cert);
    RSA *rsa_key = EVP_PKEY_get1_RSA(public_key);
    int key_length = RSA_size(rsa_key) * BITS_IN_BYTE;
    RSA_free(rsa_key);
    if (key_length<MAX_BITS){
        return 0;
    }else {
        return 1;
    }
}

int validate_basic_constraints(X509 *cert){
    BASIC_CONSTRAINTS *bs;
    bs = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL);
    if (bs->ca){
        BASIC_CONSTRAINTS_free(bs);
        return 0;
    }
    BASIC_CONSTRAINTS_free(bs);
    return 1;
}

int validate_extended_key_usage(X509 *cert){
    int usageId = 0;
    const char *kuValue = NULL;
    STACK_OF(ASN1_OBJECT) *extKu = (STACK_OF(ASN1_OBJECT) *)X509_get_ext_d2i(cert, NID_ext_key_usage,NULL, NULL);
    if (extKu == NULL) {
		fprintf(stderr, "Error in extracting Extended Key Usage");
	}

    while (sk_ASN1_OBJECT_num(extKu) > 0){
        usageId = OBJ_obj2nid(sk_ASN1_OBJECT_pop(extKu));
        kuValue = OBJ_nid2sn(usageId);
        if (strcmp(kuValue,"serverAuth") == 0) {
            return 1;
        }
    }
    return 0;
}

void write_to_file(NODE *data) {
    FILE *f = fopen(FILENAME_TO_WRITE, "w");
    if (f == NULL){
        fprintf(stderr, "Error in writing CSV filename");
        exit(EXIT_FAILURE);
    }
    while (data) {
        // you might want to check for out-of-disk-space here, too
        fprintf(f, "%s,%s,%d\n", data->certificate, data->url, data->valid);
        data = data->next;
    }
    fclose(f);
}

void free_data(NODE *head) {
    NODE *next, *current;
    current = head;
    while (current) {
        next = current->next;
        free(current->certificate);
        free(current->url);
        free(current);
        current = next;
    }
}
