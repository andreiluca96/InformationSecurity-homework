INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -I$(INC) -L$(LIB) -o encrypt encrypt_file.c -lcrypto -ldl
	gcc -I$(INC) -L$(LIB) -o out ex1.c -lcrypto -ldl
