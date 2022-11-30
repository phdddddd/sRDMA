#!/bin/bash
echo "Start running all tests"

./latency_bench.sh  
./latency_bench.sh --memkey
./latency_bench.sh --drkey
./latency_bench.sh --memkey --drkey
 

for P in {1..8} ; do ./bandwidth_bench_multi.sh --threads=${P} ; done 
for P in {1..8} ; do ./bandwidth_bench_multi.sh --threads=${P} --memkey ; done 
for P in {1..8} ; do ./bandwidth_bench_multi.sh --threads=${P} --drkey ; done 
for P in {1..8} ; do ./bandwidth_bench_multi.sh --threads=${P} --drkey --memkey ; done 


for P in {1..8} ; do ./bandwidth_bench_multi.sh --threads=${P} --read ; done 
for P in {1..8} ; do ./bandwidth_bench_multi.sh --threads=${P} --read --memkey ; done 
for P in {1..8} ; do ./bandwidth_bench_multi.sh --threads=${P} --read --drkey; done 
for P in {1..8} ; do ./bandwidth_bench_multi.sh --threads=${P} --read --memkey --drkey; done 


./bandwidth_rw_bench.sh --threads=8  --readprob=5
./bandwidth_rw_bench.sh --threads=8 --drkey --readprob=5
./bandwidth_rw_bench.sh --threads=8 --memkey --readprob=5
./bandwidth_rw_bench.sh --threads=8 --drkey --memkey --readprob=5


./bandwidth_rw_bench.sh --threads=8  --readprob=50
./bandwidth_rw_bench.sh --threads=8 --drkey --readprob=50
./bandwidth_rw_bench.sh --threads=8 --memkey --readprob=50
./bandwidth_rw_bench.sh --threads=8 --drkey --memkey --readprob=50

./bandwidth_rw_bench.sh --threads=8  --readprob=95
./bandwidth_rw_bench.sh --threads=8 --drkey --readprob=95
./bandwidth_rw_bench.sh --threads=8 --memkey --readprob=95
./bandwidth_rw_bench.sh --threads=8 --drkey --memkey --readprob=95

./trace_bench_multi.sh --threads=5 
./trace_bench_multi.sh --threads=5  --drkey
./trace_bench_multi.sh --threads=5  --memkey
./trace_bench_multi.sh --threads=5  --drkey --memkey


