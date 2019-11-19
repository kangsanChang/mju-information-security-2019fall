/*
 ============================================================================
 Name        : rsa_lab.c
 Author      : kangsan
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

int main(void) {
	// Generate RSA key pair (on Alice)
	RSA *alice_keypair = RSA_generate_key(2048, 3, NULL, NULL);
	if(alice_keypair == NULL){
		goto cleanup;
	}

	// Serialize PSA Public Key
	BIO *pub = BIO_new(BIO_s_mem());
	if(pub == NULL){
		goto cleanup;
	}

	PEM_write_bio_RSAPublicKey(pub, alice_keypair); // RSA structure 에서 public key만 빼서 넣어줌

	size_t pub_len = BIO_pending(pub);
	printf("pub_len = %d\n", pub_len);
	char *alice_pubkey = malloc(pub_len+1);
	if(alice_pubkey == NULL) {
		goto cleanup;
	}

	BIO_read(pub, alice_pubkey, pub_len);

	alice_pubkey[pub_len] = '\0';

	printf("Alice's public key :\n%s\n", alice_pubkey);

	// Serialize RSA private key
	BIO *pri = BIO_new(BIO_s_mem());
	if(pri == NULL){
		goto cleanup;
	}

	PEM_write_bio_RSAPrivateKey(pri, alice_keypair, NULL, NULL, 0, NULL, NULL); // Private Key 빼낼 때 보다 더 param 많음

	size_t pri_len = BIO_pending(pri);
	printf("pri_len = %d\n", pri_len);
	char *alice_prikey = malloc(pri_len+1);
	if(alice_prikey == NULL) {
		goto cleanup;
	}

	BIO_read(pri, alice_prikey, pri_len);

	alice_prikey[pri_len] = '\0';

	printf("Alice's private key :\n%s\n", alice_prikey);


	// De-Serialize the public key (Bob's side)
	BIO *pub2 = BIO_new_mem_buf(alice_pubkey, -1); // deserialization 용 buffer 생성
	if (pub2 == NULL){
		goto cleanup;
	}

	BIO_write(pub2, alice_pubkey, pub_len); // (char*)alice_pubkey -> (BIO*)pub2

	RSA *alice_rsa_pubkey = NULL;
	int result = PEM_read_bio_RSAPublicKey(pub2, &alice_rsa_pubkey, NULL, NULL); // (BIO*)pub2 -> (RSA*)alice_rsa_pubkey, pubkey를 가리키는 주소의 주소가 필요(double pointer)
	if(result == 0){
		goto cleanup;
	}

	// RSA public key Encryption (Alice's side)
	char *ctxt = malloc(RSA_size(alice_rsa_pubkey));
	printf("RSA_size(alice_rsa_pubkey)=%d\n", RSA_size(alice_rsa_pubkey));
	if(ctxt==NULL){
		goto cleanup;
	}

	char *msg = "Hello!! world this is test message";

	int ctxt_len = RSA_public_encrypt(strlen(msg)+1, msg, ctxt, alice_rsa_pubkey, RSA_PKCS1_OAEP_PADDING); // enc 성공 시 ctxt 의 길이나옴
	if(ctxt_len == -1){
		goto cleanup;
	}
	printf("ctxt_len=%d\n",ctxt_len);

	for(int i=0; i<ctxt_len;i++){
		printf("0x%X", ctxt[i]);
	}
	printf("\n");

	// RSA Private key Deserialize 후 Decryption 해보기

    // De-Serialize the private key (Bob's side)
    BIO *pri2 = BIO_new_mem_buf(alice_prikey, -1); // deserialization 용 buffer 생성
    if (pri2 == NULL)
    {
        goto cleanup;
    }

    result = BIO_write(pri2, alice_prikey, pri_len); // (char*)alice_pubkey -> (BIO*)pub2

    RSA *alice_rsa_prikey = NULL;
    result = PEM_read_bio_RSAPrivateKey(pri2, &alice_rsa_prikey, NULL, NULL); // (BIO*)pub2 -> (RSA*)alice_rsa_pubkey, pubkey를 가리키는 주소의 주소가 필요(double pointer)
    if (result == 0)
    {
        goto cleanup;
    }

    // Decrypt with Private Key
    unsigned char *decrypt = malloc(RSA_size(alice_rsa_prikey));
    int dtxt_len = RSA_private_decrypt(ctxt_len, ctxt, decrypt, alice_rsa_prikey, RSA_PKCS1_OAEP_PADDING);
    if (dtxt_len == -1)
    {
        goto cleanup;
    }
    printf("dtxt_len=%d\n", dtxt_len);
    printf("Decrypted MSG: %s\n", decrypt);

    // 할당 중 NULL 이 나오면 그 위까지 선언한 애들을 다 cleanup
cleanup:
	if(alice_keypair != NULL) RSA_free(alice_keypair);
	if(pub != NULL) BIO_free_all(pub);
	if(alice_pubkey != NULL) free(alice_pubkey);
	if(pri != NULL) BIO_free_all(pri);
	if(alice_prikey != NULL) free(alice_prikey);
	if(pub2 != NULL) BIO_free_all(pub2);
	if(ctxt != NULL) free(ctxt);
    if(pri2 != NULL) BIO_free_all(pri2);

	return EXIT_SUCCESS;
}
