
CC = gcc

CFLAGS = -Wall -O

#设置头文件目录
HEADER_PATH = ./include

#设置GCC搜素目录
VPATH = ./src

#设置依赖文件
OBJECTS = rbw_sniffer.o rb_frame_parser.o rb_utils.o rb_radiotap_mgt.o

rbw_sniffer : $(OBJECTS)
	$(CC)	$(CFLAGS) $(OBJECTS) -o rbw_sniffer -lpcap

rbw_sniffer.o : rbw_sniffer.c
	$(CC) $(CFLAGS) -c $(VPATH)/rbw_sniffer.c -o rbw_sniffer.o -I$(HEADER_PATH)

rb_frame_parser.o : rb_frame_parser.c
	$(CC) $(CFLAGS) -c $(VPATH)/rb_frame_parser.c -o rb_frame_parser.o -I$(HEADER_PATH)

rb_utils.o : rb_utils.c
	$(CC) $(CFLAGS) -c $(VPATH)/rb_utils.c -o rb_utils.o -I$(HEADER_PATH)

rb_radiotap_mgt.o : rb_radiotap_mgt.c
	$(CC) $(CFLAGS) -c $(VPATH)/rb_radiotap_mgt.c -o rb_radiotap_mgt.o -I$(HEADER_PATH)

clean :
	rm rbw_sniffer *.o
