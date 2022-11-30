# sRDMA

## Required hardware and software
 * Two SmartNICs running linux (e.g. Broadcom PS225).
 * rdma-core: RDMA Core Userspace Libraries 
 * openssl: a general-purpose cryptography library.
 
## Building
The whole project can be compiled using a single `Makefile`.
The makefile should be  manually configured by changing the absolute path to openssl.
sRDMA depends on [openssl 1.1.1a](https://www.openssl.org/source/old/1.1.1/openssl-1.1.1a.tar.gz)

### SmartNICs
The `nic` application must be compiled on the SmartNICs, since they are usually equipped with ARM CPUs. The dependent libraries such as openssl must be also compiled on the SmartNICs. You can compile only `nic ` application using `make nic`.

## Running the benchmarks
Refer to the bash scripts `./SCRIPT.sh --help`. 
To run all the experiments from the paper, one can use `./all_tests.sh`.
Note that IP addresses of hosts and smartnics must be changed manually in each bash script. 

### Security codes
sRDMA supports various security codes to protect RDMA connections. The full list of supported security codes is available at
`security/security.hpp`.

## Running secure HERD
Please, refer to `../HERD_secure/herd/README-sRDMA.md`.

## sRDMA connection logic
Each script launches applications in the following order:
 * smartnic1
 * smartnic2
 * host2
 * host1

```
+------------------+                +------------------+
|                  |                |                  |
|      client      |                |       host       |
|                  |                |                  |
|     at host1     |                |    at host2      |
|                  |                |                  |
|       ^^         |                |       ^^         |
|       ||         |                |       ||         |
|      PCIe        |                |      PCIe        |
|  +----||------+  |                |  +----||------+  |
|  |    vv    <----------QP RC---------->   vv      |  |
|  | smartnic1  |  |                |  | smartnic2  |  |
|  |            |  |                |  |            |  |
|  +------------+  |                |  +------------+  | 
|                  |                |                  |
+------------------+                +------------------+

```

## Contact
Konstantin Taranov (ktaranov@inf.ethz.ch)

