#!/bin/bash
define(){ IFS='\n' read -r -d '' ${1} || true; }
declare -A pids
redirection=( "> out" "2> err" "< /dev/null" )
define HELP <<'EOF'
Script for starting trace bandwidth benchmark
Note: fix manualy ip addresses of hosts and smartnics!
usage  : $0 [options]
options: 
  [--epath=DIR]              # Execution path. Default PWD 
  [--threads=N]              # numder of threads. Default 1
  [--test=CODE]              # test specific protection code
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
"0x0000" "0x1001" "0x1002" "0x1003" "0x1004" "0x1005" "0x1006" "0x1007" "0x1008" "0x1009" 
"0x2001" "0x2002" "0x2003" "0x2004" "0x2005" "0x2006" "0x2007" "0x2008" "0x2009" 
"0x3001" "0x3002" "0x3003" "0x3004" "0x3005" 
"0x4001" "0x4002" "0x4003" "0x4004" "0x4005" 
"0x5001" "0x5002" "0x5003" "0x5004" "0x5005"
)


if [ ! -z "${TEST}" ]  
then
declare -a goal=(${TEST})
fi


declare -a traces=("Financial1" "Financial2" "WebSearch1" "WebSearch2" "WebSearch3")


#http://skuld.cs.umass.edu/traces/storage/Financial1.spc.bz2

for(( t=0; t<${#traces[@]}; t=t+1));    do
cmd=( "wget" "http://skuld.cs.umass.edu/traces/storage/${traces[t]}.spc.bz2")
echo "Executing: ${cmd[@]}"
${cmd[@]}
cmd=( "bzip2" "-d ${traces[t]}.spc.bz2")
echo "Executing: ${cmd[@]}"
${cmd[@]}
cmd=( "./parse_trace" "-i ${traces[t]}.spc" "-o ${traces[t]}.bin")
echo "Executing: ${cmd[@]}"
${cmd[@]}

for(( i=0; i<${#goal[@]}; i=i+1));    do


   echo "Starting servers..."
   Start "${goal[i]}"
   echo "done!"
   sleep 1
   echo "Starting test ${goal[i]}"
   cmd=("timeout 4m" "./client_tracer" "--smartnic=${nic1}" "--another=${host2}"  "-i ${traces[t]}.bin" "-o newclttrace_${traces[t]}_${THREADS}_${goal[i]}${DRKEYNAME}${MEMKEYNAME}.txt" "--crypto=${goal[i]}" "--sendsize=160" "--outstand=96"  "--threads=${THREADS}"  "--workers=${THREADS}" "${DRKEY}" "${MEMKEY}" ) #"--memkey"  "--drkey"
   echo "Executing: ${cmd[@]}"
   ${cmd[@]}

   Stop
   sleep 2
done

rm -f *.bin
rm -f *.spc

echo "All Traces are done"
done



########################################################################



