#!/bin/bash
define(){ IFS='\n' read -r -d '' ${1} || true; }
declare -A pids
redirection=( "> out" "2> err" "< /dev/null" )
define HELP <<'EOF'
Script for starting mixed bandwidth benchmark
Note: fix manualy ip addresses of hosts and smartnics!
usage  : $0 [options]
options: 
  [--epath=DIR]              # Execution path. Default PWD  
  [--threads=N]              # numder of threads. Default 1
  [--test=CODE]              # test specific protection code
  [--readprob]               # Probability of read  Default 0
  [--drkey]                  # with Secure PD
  [--memkey]                 # with Extended Memory Protection
EOF


# the setting is (host1 -- nic1) -- (nic2 -- host2)
# the host1 is the current host
nic1=192.168.212.146
nic2=192.168.212.148
host2=192.168.212.147

usage () {
    echo -e "$HELP"
}

ErrorAndExit () {
  echo "ERROR: $1"
  exit 1
}

ForceAbsolutePath () {
  case "$2" in
    /* )
      ;;
    *)
      ErrorAndExit "Expected an absolute path for $1"
      ;;
  esac
}

Start() {
    run_smartnic=( "${EPATH}/nic" "--packetsize=2048" "--threads=${THREADS}" "-o ${EPATH}/debug.txt") 
    cmd=("ssh" "$USER@${nic1}" "nohup" "${run_smartnic[@]}" "${redirection[@]}" "&" "echo \$!" )
    pids["${nic1}"]=$("${cmd[@]}")
    echo -e "COMMAND: "${cmd[@]}
    
    sleep 1

    run_smartnic=( "${EPATH}/nic" "--packetsize=2048" "--anothernic=${nic1}" "--threads=${THREADS}" "-o ${EPATH}/debug.txt") 
    cmd=("ssh" "$USER@${nic2}" "nohup" "${run_smartnic[@]}" "${redirection[@]}" "&" "echo \$!" )
    pids["${nic2}"]=$("${cmd[@]}")
    echo -e "COMMAND: "${cmd[@]}




    sleep 1
    run_host=( "${EPATH}/host" "--crypto=$1" "--threads=${THREADS}"  "--workers=${THREADS}" "--smartnic=${nic2}" "${DRKEY}" "${MEMKEY}")
    cmd=( "ssh" "$USER@${host2}" "nohup" "${run_host[@]}" "${redirection[@]}" "&" "echo \$!" )
    pids["${host2}"]=$("${cmd[@]}")    
    echo -e "COMMAND: "${cmd[@]}

    echo -e "\tinitial nodes: ${!pids[@]}"
    echo -e "\t...and their PIDs: ${pids[@]}"
 
}

Stop() {
    for k in "${!pids[@]}"
    do
        cmd=( "ssh" "$USER@$k" "kill -s 9" "${pids[$k]}" )
        echo "Executing: ${cmd[@]}"
        $("${cmd[@]}")
    done
}

EPATH=${PWD}
DRKEY=""
DRKEYNAME=""
MEMKEY=""
MEMKEYNAME=""
THREADS="1"
READPROB="0"

TEST=""

for arg in "$@"
do
    case ${arg} in
    --help|-help|-h)
        usage
        exit 1
        ;;
    --test=*)
        TEST=`echo $arg | sed -e 's/--test=//'`
        TEST=`eval echo ${TEST}`    # tilde and variable expansion
        ;;
    --readprob=*)
        READPROB=`echo $arg | sed -e 's/--readprob=//'`
        READPROB=`eval echo ${READPROB}`    # tilde and variable expansion
        ;;
    --drkey)
        DRKEY="--drkey"
        DRKEYNAME="_drkey"
        ;;
    --memkey)
        MEMKEY="--memkey"
        MEMKEYNAME="_memkey"
        ;;
    --epath=*)
        EPATH=`echo $arg | sed -e 's/--epath=//'`
        EPATH=`eval echo ${EPATH}`    # tilde and variable expansion
        ForceAbsolutePath "--epath" "${EPATH}"
        ;;
    --threads=*)
        THREADS=`echo $arg | sed -e 's/--threads=//'`
        THREADS=`eval echo ${THREADS}`    # tilde and variable expansion
        ;;
    esac
done


# Handle SIGINT to ensure a clean exit
trap 'echo -ne "Stop all servers..." && Stop && echo "done" && exit 1' INT

########################################################################


declare -a goal=(
 "0x1001"
)
 
if [ ! -z "${TEST}" ]  
then
declare -a goal=(${TEST})
fi


for(( i=0; i<${#goal[@]}; i=i+1));    do

  echo "Starting servers..."
  Start "${goal[i]}"
  echo "done!"
  sleep 1


  echo "Starting test ${goal[i]}"
  cmd=("timeout 1m" "${EPATH}/client_rw_bw" "--each=0.01" "--smartnic=${nic1}" "--another=${host2}" "-o newcltrwbw_${READPROB}_${THREADS}_${goal[i]}${DRKEYNAME}${MEMKEYNAME}.txt" "--readprob=${READPROB}" "--crypto=${goal[i]}" "--sendsize=160" "--outstand=96"  "--threads=${THREADS}"  "--workers=${THREADS}" "${DRKEY}" "${MEMKEY}" ) #"--memkey"  "--drkey"
  echo "Executing: ${cmd[@]}"
  ${cmd[@]}

  Stop
  sleep 1
done


echo "Trace is done"




########################################################################



