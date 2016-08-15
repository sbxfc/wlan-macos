
CC = gcc

CFLAGS = -Wall -O

#设置头文件目录
HEADER_PATH = .

#设置GCC搜素目录
VPATH = .

deauth : deauth.o
	$(CC)	$(CFLAGS) deauth.o -o deauth -lpcap

deauth.o : deauthentication.c
	$(CC) $(CFLAGS) -c $(VPATH)/deauthentication.c -o deauth.o -I$(HEADER_PATH)

clean :
	rm deauth *.o
