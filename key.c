#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<openssl/bn.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>

int main(int argc, char *argv[]){
    // generate RSA key
    RSA *rsa = RSA_new();
    BIGNUM *bne = BN_new();
    BN_set_word(bne, 65537);
    RSA_generate_key_ex(rsa, 1024, bne, NULL);
    BIO *bp_public = NULL, *bp_private = NULL;

    printf("BIGNUM: %s", BN_bn2hex(bne));

    // save public key
    bp_public = BIO_new_file("pubkey.pem", "w");
    PEM_write_bio_RSAPublicKey(bp_public, rsa);

    // save private key
    bp_private = BIO_new_file("prikey.pem", "w");
    PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);

    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(rsa);
    BN_free(bne);

    return 0;
}
