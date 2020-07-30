ALL: hello key encdec

hello: hello.c
	gcc -o hello hello.c -lcrypto

key: key.c
	gcc -o key key.c -lcrypto

encdec: encdec.c
	gcc -o encdec encdec.c -lcrypto

clean:
	rm aes_key.dec aes_key.enc prikey.pem pubkey.pem decrypted encrypted hello key encdec
