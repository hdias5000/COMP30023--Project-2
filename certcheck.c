/***
Program Written By Hasitha Dias
Student ID: 789929
University/GitLab Username: diasi
Email: i.dias1@student.unimelb.edu.au
Last Modified Date: 24/05/2018
***/

#include "certcheck.h"

void main(int argc, char const *argv[]) {
    NODE *head,*list;
    //reads the file
    head = read_CSVfile(head, argv[1]);

    list = head;
    //checks each certificate
    while (list){
        list->valid = check(list->certificate, list->url);
        list = list->next;
    }
    //writes to new CSV file
    write_to_file(head);
    free_data(head);
}

NODE* read_CSVfile(NODE *head, const char* filename){
    char buffer[BUFFER_SIZE], *record, *line;
    FILE *fstream = fopen(filename, "r");
    NODE *current, *new = 0;
    int count_nodes = 0;

    //checks if file read correctly
    if(fstream == NULL){
        fprintf(stderr, "Error in reading CSV filename\n");
        exit(EXIT_FAILURE);
    }

    //saves each line from CSV file
    while((line=fgets(buffer,sizeof(buffer),fstream))!=NULL){
        new  = (NODE *)malloc(sizeof(NODE));
        assert(new);

        record = strtok(line,COMMA);
        new->certificate = malloc(sizeof(record));
        assert(new->certificate);
        strcpy(new->certificate, record) ;

        record = strtok(NULL,EOL);
        new->url = malloc(sizeof(record));
        assert(new->url);
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

    //reads and saves the certificate
    cert = read_certificate(cert,certificate);

    //validates each(required) aspect of the certificate
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
    BIO *cert_bio = NULL;
    X509_NAME *cert_issuer = NULL;
    X509_CINF *cert_inf = NULL;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    //create BIO object to read certificate
    cert_bio = BIO_new(BIO_s_file());

    //reads certificate into BIO
    if (!(BIO_read_filename(cert_bio, certificate))){
        fprintf(stderr, "Error in reading cert BIO filename\n");
        exit(EXIT_FAILURE);
    }

    //loads certificate from bio
    if (!(cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL))){
        fprintf(stderr, "Error in loading certificate\n");
        exit(EXIT_FAILURE);
    }
    return cert;
    BIO_free_all(cert_bio);
}

int validate_date(X509 *cert){
    //saves not before and not after in ASN1_TIME format
    ASN1_TIME *not_before = X509_get_notBefore(cert);
    ASN1_TIME *not_after = X509_get_notAfter(cert);

    int sec,day,sec1,day1;

    //both time differences are checked to see if there are any discrepencies
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

int validate_CN(const char *hostname, X509 *server_cert) {
	int cn_location = -1;
	X509_NAME_ENTRY *cn_entry = NULL;
	ASN1_STRING *cn_asn1 = NULL;
	char *cn_string = NULL;

	//finds the position of the Common Name field in the Subject field of the
    //certificate
	cn_location = X509_NAME_get_index_by_NID(X509_get_subject_name(server_cert),
        NID_commonName, -1);
	if (cn_location < 0) {
        fprintf(stderr, "Error in finding position of Common Name\n");
		return 0;
	}

	//extract the Common Name field
	if (!(cn_entry = X509_NAME_get_entry(X509_get_subject_name(server_cert),
        cn_location))) {
        fprintf(stderr, "Error in extracting Common Name\n");
		return 0;
	}

	//convert the Common Name field to a string
	if (!(cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry))) {
        fprintf(stderr, "Error in converting Common Name field to string\n");
		return 0;
	}
	cn_string = (char *) ASN1_STRING_data(cn_asn1);

    if (check_wildcards(hostname,cn_string)) {
        return 1;
    }
    return 0;
}

int validate_SAN(const char *hostname, X509 *server_cert) {
	int i;
	int san_count = -1;
	STACK_OF(GENERAL_NAME) *san_list = NULL;

	//extracts the names within the SAN extension from the certificate
	if (!(san_list = X509_get_ext_d2i(server_cert, NID_subject_alt_name, NULL,
        NULL))) {
		fprintf(stderr, "SAN does not exist/Error in extracting SAN\n");
        return 0;
	}
	san_count = sk_GENERAL_NAME_num(san_list);

	//check each name within the extension
	for (i=0; i<san_count; i++) {
		const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_list, i);
        char *dns_name = ASN1_STRING_data(current_name->d.dNSName);
        //checks wildcard
        if (check_wildcards(hostname,dns_name)) {
            sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
            return 1;
        }
	}

	sk_GENERAL_NAME_pop_free(san_list, GENERAL_NAME_free);
	return 0;
}

int check_wildcards(const char* hostname, char* dns){
    int diff = 0;
    char firstletter[TWO_CHARACTERS];
    //extract the first character from Common Name of certificate
    firstletter[0] = dns[0];
    firstletter[1]=TERMINATION_CHARACTER;

    //checks if the first character is a star and if so handles for wildcard
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
    //retrieves RSA key from certificate
    EVP_PKEY *public_key = NULL;
    RSA *rsa_key = NULL;

    //extracts(decodes) the public key from the certificate
    if (!(public_key = X509_get_pubkey(cert))) {
		fprintf(stderr, "Error in extracting Public Key\n");
        return 0;
	}

    //extracts the referenced key in public_key
    if (!(rsa_key = EVP_PKEY_get1_RSA(public_key))) {
		fprintf(stderr, "Error in extracting RSA key\n");
        return 0;
	}

    //converts key_length in RSA modulus bytes to bits
    int key_length = RSA_size(rsa_key) * BITS_IN_BYTE;
    RSA_free(rsa_key);

    if (key_length<MAX_BITS){
        return 0;
    }else {
        return 1;
    }
}

int validate_basic_constraints(X509 *cert){
    BASIC_CONSTRAINTS *bc = NULL;

    //extracts the Basic Constrainsts extension
    if (!(bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL))) {
		fprintf(stderr, "Error in extracting Basic Constrainsts\n");
        return 0;
	}

    if (bc->ca){
        BASIC_CONSTRAINTS_free(bc);
        return 0;
    }
    BASIC_CONSTRAINTS_free(bc);
    return 1;
}

int validate_extended_key_usage(X509 *cert){
    int valueID = 0;
    const char *extku_value = NULL;
    STACK_OF(ASN1_OBJECT) *ext_key_usage = NULL;

    //extracts the Extended Key Usage extension
    if (!(ext_key_usage = X509_get_ext_d2i(cert, NID_ext_key_usage,NULL, NULL))) {
		fprintf(stderr, "Error in extracting Extended Key Usage\n");
        return 0;
	}

    //checks all values of ext key usage to match TLS Server Authentication
    while (sk_ASN1_OBJECT_num(ext_key_usage) > 0){
        //extracts the Extended Key Usage ValueID
        if (!(valueID = OBJ_obj2nid(sk_ASN1_OBJECT_pop(ext_key_usage)))) {
    		fprintf(stderr, "Error in extracting Extended Key Usage ValueID\n");
            return 0;
    	}

        //extracts the Extended Key Usage extension
        if (!(extku_value = OBJ_nid2sn(valueID))) {
    		fprintf(stderr, "Error in extracting Extended Key Usage Value\n");
            return 0;
    	}

        if (strcmp(extku_value,"serverAuth") == 0) {
            return 1;
        }
    }
    return 0;
}

void write_to_file(NODE *data) {
    FILE *f = fopen(FILENAME_TO_WRITE, "w");
    if (f == NULL){
        fprintf(stderr, "Error in writing CSV filename\n");
        exit(EXIT_FAILURE);
    }
    while (data) {
        //formatting the data accordingly
        fprintf(f, "%s,%s,%d\n", data->certificate, data->url, data->valid);
        data = data->next;
    }
    fclose(f);
}

void free_data(NODE *head) {
    NODE *next, *current;
    current = head;
    //frees data of each node to prevent memory leaks
    while (current) {
        next = current->next;
        free(current->certificate);
        free(current->url);
        free(current);
        current = next;
    }
}
