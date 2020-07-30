#include<openssl/aes.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

unsigned char indata[AES_BLOCK_SIZE];
unsigned char outdata[AES_BLOCK_SIZE];
unsigned char decryptdata[AES_BLOCK_SIZE];

unsigned char IV[] = "\x0A\x91\x72\x71\x6A\xE6\x42\x84\x09\x88\x5B\x8B\x82\x9C\xCB\x05";
// unsigned char userkey[] =

AES_KEY key;

void encrypt(){
    FILE *ifp, *ofp;
    ifp = fopen("signature", "r+");
    ofp = fopen("encrypted", "w+");
    int postion = 0;
    int bytes_read, bytes_write;
    while(1){
        unsigned char ivec[AES_BLOCK_SIZE];
        memcpy(ivec, IV, AES_BLOCK_SIZE);
        bytes_read = fread(indata, 1, AES_BLOCK_SIZE, ifp);
        AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &postion, AES_ENCRYPT);
        bytes_write = fwrite(outdata, 1, bytes_read, ofp);
        if(bytes_read<AES_BLOCK_SIZE){
            break;
        }
    }
    fclose(ifp);
    fclose(ofp);
}

void decrypt(){
    FILE *ifp, *ofp;
    ifp = fopen("encrypted", "r+");
    ofp = fopen("decrypted", "w+");
    int postion = 0;
    int bytes_read, bytes_write;
    while(1){
        unsigned char ivec[AES_BLOCK_SIZE];
        memcpy(ivec, IV, AES_BLOCK_SIZE);
        bytes_read = fread(outdata, 1, AES_BLOCK_SIZE, ifp);
        AES_cfb128_encrypt(outdata, decryptdata, bytes_read, &key, ivec, &postion, AES_ENCRYPT);
        bytes_write = fwrite(decryptdata, 1, bytes_read, ofp);
        if(bytes_read<AES_BLOCK_SIZE){
            break;
        }
    }
    fclose(ifp);
    fclose(ofp);
}

int main(){
    FILE *fkey = fopen("aes_key.dec", "r");
    unsigned char *userkey[17];
    fscanf(fkey, "%s", userkey);

    AES_set_encrypt_key(userkey, 128, &key);

    encrypt();
    decrypt();
}
