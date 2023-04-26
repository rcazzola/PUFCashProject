
all:
	gcc aes_128_ecb_openssl.c aes_test.c -lssl -lcrypto -o aes_test

	gcc aes_256_cbc_openssl.c aes_test_256.c -lssl -lcrypto -o aes_test_256

clean:
	rm -rf aes_test
	rm -rf aes_test_256
	rm -rf *.o

