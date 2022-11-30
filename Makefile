APPS = nic  client_lat client memory_protection_bench client_rw_bw client_bw_multi nic generate_rw_trace parse_trace client_tracer  host  

# fix path to openssl
opensslpath=/home/libs/


HOSTNAME=$(shell hostname)

#host1
ifeq ($(HOSTNAME), gauss)
    APPS=client client_lat parse_trace client_tracer client_bw_multi  generate_rw_trace 
endif

#nic1
ifeq ($(HOSTNAME), smartnic16)
    APPS=nic
endif

#nic2
ifeq ($(HOSTNAME), smartnic08)
    APPS=nic
endif

#host2
ifeq ($(HOSTNAME), galilei) 
    APPS= host
endif



LDFLAGS =  -libverbs -lrdmacm -lpthread -lev -ldl  -L$(opensslpath)/lib/ -lcrypto  -Wl,-rpath=$(opensslpath)/lib/
CFLAGS += -Wall -std=c++11 -I./ -I$(opensslpath)/include/ #-g -D_GNU_SOURCE

all: CFLAGS += -O2
all: ${APPS}

nic: clean
	g++ nic.cpp -I$(opensslpath)/include/  $(CFLAGS) $(LDFLAGS) -lboost_system  -o nic

memory_protection_bench: clean
	g++ memory_protection_bench.cpp ./utilities/get_clock.c -I$(opensslpath)/include/  $(CFLAGS) $(LDFLAGS) -lboost_system -D_DEFAULT_SOURCE -o memory_protection_bench

parse_trace: clean
	g++ parse_trace.cpp $(CFLAGS) $(LDFLAGS)  -o parse_trace

generate_rw_trace: clean
	g++ generate_rw_trace.cpp $(CFLAGS) $(LDFLAGS)  -o generate_rw_trace

client: clean
	g++ client.cpp $(CFLAGS) $(LDFLAGS)  -o client

client_lat: clean
	g++ client_lat.cpp $(CFLAGS) $(LDFLAGS)   -o client_lat

client_bw_multi: clean
	g++ client_bw_multi.cpp $(CFLAGS) $(LDFLAGS)   -o client_bw_multi

client_rw_bw: clean
	g++ client_rw_bw.cpp $(CFLAGS) $(LDFLAGS)   -o client_rw_bw

client_tracer: clean
	g++ client_tracer.cpp $(CFLAGS) $(LDFLAGS)   -o client_tracer

host: clean
	g++ host.cpp $(CFLAGS) $(LDFLAGS)  -o host

openssltest: clean
	g++ openssltest.cpp -I$(opensslpath)/include/ $(CFLAGS) $(LDFLAGS) -o openssltest 

clean:
	$(foreach fname,${APPS}, rm -f ${fname})
	rm -f *.spc
	rm -f *.bin

git:
	git pull
	make all


debug: CFLAGS += -DDEBUG -g -O0
debug: ${APPS}

.DELETE_ON_ERROR:
.PHONY: all clean
