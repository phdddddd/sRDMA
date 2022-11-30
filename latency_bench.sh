#!/bin/bash
define(){ IFS='\n' read -r -d '' ${1} || true; }
declare -A pids
redirection=( "> out" "2> err" "< /dev/null" )
define HELP <<'EOF'
Script for starting latency benchmark
Note: fix manualy ip addresses of hosts and smartnics!
usage  : $0 [options]
options: 
  [--epath=DIR]              # Execution path. Default PWD  
  [--drkey]                  # with Secure PD
  [--memkey]                 # with Extended Memory Protection
EOF


# the setting is (host1 -- nic1) -- (nic2 -- host2)
# the host1 is the current host
nic1=192.198.1.10
nic2=192.198.1.40
host2=192.198.1.30

#sleep 1
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
    run_smartnic=( "${EPATH}/nic" "--packetsize=4096" "--threads=1" "-o ${EPATH}/debug.txt") 
    cmd=("ssh" "$USER@${nic1}" "nohup" "${run_smartnic[@]}" "${redirection[@]}" "&" "echo \$!" )
    pids["${nic1}"]=$("${cmd[@]}")
    echo -e "COMMAND: "${cmd[@]}
    
    sleep 1

    run_smartnic=( "${EPATH}/nic" "--packetsize=4096" "--anothernic=${nic1}" "--threads=1" "-o ${EPATH}/debug.txt") 
    cmd=("ssh" "$USER@${nic2}" "nohup" "${run_smartnic[@]}" "${redirection[@]}" "&" "echo \$!" )
    pids["${nic2}"]=$("${cmd[@]}")
    echo -e "COMMAND: "${cmd[@]}

    sleep 1
    run_host=( "${EPATH}/host" "--crypto=$1" "--smartnic=${nic2}" "${DRKEY}" "${MEMKEY}")
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

for arg in "$@"
do
    case ${arg} in
    --help|-help|-h)
        usage
        exit 1
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
    esac
done


# Handle SIGINT to ensure a clean exit
trap 'echo -ne "Stop all servers..." && Stop && echo "done" && exit 1' INT

########################################################################
 
declare -a goal=("0x0000" "0x1001" "0x1002" "0x1003" "0x1004" "0x1005" "0x1006" "0x1007" "0x1008" "0x1009" 
"0x2001" "0x2002" "0x2003" "0x2004" "0x2005" "0x2006" "0x2007" "0x2008" "0x2009" 
"0x3001" "0x3002" "0x3003" "0x3004" "0x3005" 
"0x4001" "0x4002" "0x4003" "0x4004" "0x4005" 
"0x5001" "0x5002" "0x5003" "0x5004" "0x5005")



for(( i=0; i<${#goal[@]}; i=i+1));    do

  echo "Starting servers..."
  Start "${goal[i]}"
  echo "done!"
  sleep 1


  echo "Starting test ${goal[i]}"
  cmd=("timeout 2m" "${EPATH}/client_lat" "--smartnic=${nic1}" "--another=${host2}" "-o newcltlat_${goal[i]}${DRKEYNAME}${MEMKEYNAME}.txt" "--len=0" "--crypto=${goal[i]}" "${DRKEY}" "${MEMKEY}" "--num=5000")
  echo "Executing: ${cmd[@]}"
  ${cmd[@]}


  Stop
  sleep 2
done


echo "Trace is done"




########################################################################



