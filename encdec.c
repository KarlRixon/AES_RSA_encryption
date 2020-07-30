#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>

#define PRIKEY "prikey.pem"
#define PUBKEY "pubkey.pem"
#define BUFFSIZE 4096

unsigned char userkey[] = "\x09\x8F\x6B\xCD\x46\x21\xD3\x73\xCA\xDE\x4E\x83\x26\x27\xB4\xF6";

char *my_encrypt(char *str, char *pubkey_path){
    RSA *rsa = NULL;
    FILE *fp = NULL;
    char *en = NULL;
    int len = 0;
    int rsa_len = 0;

    if((fp = fopen(pubkey_path, "r")) == NULL){
        return NULL;
    }

    // read public key
    if((rsa = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL)) == NULL){
        return NULL;
    }

    RSA_print_fp(stdout, rsa, 0);

    len = strlen(str);
    rsa_len = RSA_size(rsa);

    en = (char *)malloc(rsa_len+1);
    memset(en, 0, rsa_len+1);

    if(RSA_public_encrypt(rsa_len, (unsigned char *)str, (unsigned char *)en, rsa, RSA_NO_PADDING)<0){
        return NULL;
    }

    RSA_free(rsa);
    fclose(fp);

    FILE *fen = fopen("aes_key.enc", "w");
    fprintf(fen, "%s", en);

    return en;
}

char *my_decrypt(char *str, char *prikey_path){
    RSA *rsa = NULL;
    FILE *fp = NULL;
    char *de = NULL;
    int rsa_len = 0;

    if((fp = fopen(prikey_path, "r")) == NULL){
        return NULL;
    }

    // read private key
    if((rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL)) == NULL){
        return NULL;
    }

    RSA_print_fp(stdout, rsa, 0);

    rsa_len = RSA_size(rsa);
    de = (char *)malloc(rsa_len+1);
    memset(de, 0, rsa_len+1);

    if(RSA_private_decrypt(rsa_len, (unsigned char *)str, (unsigned char *)de, rsa, RSA_NO_PADDING)<0){
        return NULL;
    }

    RSA_free(rsa);
    fclose(fp);

    FILE *fde = fopen("aes_key.dec", "w");
    fprintf(fde, "%s", de);

    return de;
}

int main(int argc, char *argv[]){
    char *src = userkey;
    char *en = NULL;
    char *de = NULL;
    printf("key  len: %d\n", sizeof(userkey));

    printf("src is: %x\n", src);

    en = my_encrypt(src, PUBKEY);
    printf("enc is: %x\n", en);

    de = my_decrypt(en, PRIKEY);
    printf("dec is: %x\n", de);

    if(en!=NULL){
        free(en);
    }
    if(de!=NULL){
        free(de);
    }
    return 0;
}
