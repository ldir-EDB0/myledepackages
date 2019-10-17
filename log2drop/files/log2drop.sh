#!/bin/ash
#
# log2drop - dropbear log parsing ban agent for OpenWRT
# hacked by Kevin D-B - heavily based on bearDropper
#   http://github.com/robzr/bearDropper - Rob Zwissler 11/2015
# 
#     "follow" mode follows syslog to process entries as they happen; generally launched via init
#        script. Responds the fastest, runs the most efficiently, but is always in memory.
# the l2db record format
#
# the IP address with '.' replaced by '_' and ':' replaced by 'i' form the record key
#
# l2db_192_168_1_1=status,time[,time...]
# right most time is the most recent

# Load UCI config variable, or use default if not set
# Args: $1 = variable name (also uci option name), $2 = default_value
uciSection='log2drop.@[0]'
uciLoadVar () { 
	local getUci
	getUci=$(uci -q get "${uciSection}.$1") || getUci="$2"
	eval "$1"=\'"$getUci"\'
}

uciLoad() {
	local tFile delim
	tFile=$(mktemp) delim=$'\n'
	[ "$1" = -d ] && { delim="$2"; shift 2; }
	if uci -q -d"$delim" get "$uciSection.$1" 2>/dev/null >"$tFile" ; then
	  sed -e "s/^\'//" -e "s/\'$//" "$tFile"
	else
	  while [ -n "$2" ]; do echo "$2"; shift; done
	fi
	rm -f "$tFile"
}

# Common config variables - edit these in /etc/config/log2drop
# or they can be overridden at runtime with command line options
#
uciLoadVar attemptCount 10
uciLoadVar attemptPeriod 12h
uciLoadVar banLength 1w
uciLoadVar logLevel 1
uciLoadVar logFacility authpriv.notice
uciLoadVar persistentStateWritePeriod -1
uciLoadVar fileStateType l2db
uciLoadVar fileStateTempPrefix /tmp/log2drop
uciLoadVar fileStatePersistPrefix /etc/log2drop

# Advanced variables, changeable via uci only (no cmdline), it is 
# unlikely that these will need to be changed, but just in case...
#
uciLoadVar syslogTag "log2drop[$$]"
uciLoadVar followModeCheckInterval 30m	# how often to attempt to expire bans when in follow mode
uciLoadVar cmdLogread 'logread'		# for tuning, ex: "logread -l250"
uciLoadVar formatLogDate '%b %e %H:%M:%S %Y'	# used to convert syslog dates

# Begin functions
#
# Clear l2db entries from environment
l2dbClear () { 
	local l2dbVar
	for l2dbVar in $(set | grep -E -e '^l2db_[0-9a-fA-F_i]*=' | cut -f1 -d= | xargs echo -n) ; do eval unset -v \'"$l2dbVar"\' ; done
	l2dbStateChange=1
}

# Returns count of unique IP entries in environment
l2dbCount () { set | grep -c -E -e '^l2db_[0-9a-fA-F_i]*=' ;}

# Loads existing l2db file into environment
# Arg: $1 = file, $2 = type (l2db/l2dbz)
l2dbLoad () { 
	local loadFile fileType
	loadFile="$1.$2" fileType="$2"
	if [ "$fileType" = l2db -a -f "$loadFile" ] ; then
# shellcheck source=/dev/null
	  . "$loadFile"
	elif [ "$fileType" = l2dbz -a -f "$loadFile" ] ; then
	  local tmpFile
	  tmpFile="$(mktemp)"
	  zcat "$loadFile" > "$tmpFile"
# shellcheck source=/dev/null
	  . "$tmpFile"
	  rm -f "$tmpFile"
	fi
	l2dbStateChange=0
}

# Saves environment l2db entries to file, Arg: $1 = file to save in
l2dbSave () { 
	local saveFile fileType
	saveFile="$1.$2" fileType="$2"
	if [ "$fileType" = l2db ] ; then
	  set | grep -E -e '^l2db_[0-9a-fA-F_i]*=' | sed -e "s/\'//g" > "$saveFile"
	elif [ "$fileType" = l2dbz ] ; then
	  set | grep -E -e '^l2db_[0-9a-fA-F_i]*=' | sed -e "s/\'//g" | gzip -c > "$saveFile"
	fi
	l2dbStateChange=0 
}

# Set l2db record status=1, update ban time flag with newest
# Args: $1=IP Address $2=timeFlag
l2dbEnableStatus () {
	local ipr newestTime
	ipr="${1//./_}"
	ipr="${ipr//:/i}"
	newestTime=$(l2dbGetTimes "$1" | sed -e 's/.* //' | xargs echo "$2" | tr ' ' '\n' | sort -un | tail -1 )
	eval l2db_"$ipr"=\'"1,$newestTime"\'
	l2dbStateChange=1
}

# Args: $1=IP Address
l2dbGetStatus () {
	l2dbGetRecord "$1" | cut -d, -f1
}

# Args: $1=IP Address
l2dbGetTimes () {
	l2dbGetRecord "$1" | cut -d, -f2-
}

# Args: $1 = IP , $2 [$3 ...] = timestamp (seconds since epoch)
l2dbAddRecord () {
	local ipr status newEpochList oldEpochList epochList
	ipr="${1//./_}" ; shift
	ipr="${ipr//:/i}"
	status="$(eval echo \"\$l2db_$ipr\" | cut -f1 -d,)"
	newEpochList="$*"
	oldEpochList="$(eval echo \"\$l2db_$ipr\" | cut -f2- -d, )"
	oldEpochList="${oldEpochList//,/ }"
	epochList=$(echo "$oldEpochList" "$newEpochList" | xargs -n 1 echo | sort -n | xargs echo -n )
	epochList="${epochList// /,}"
	logLine 3 "newEpochlist ${newEpochList} oldEpochList ${oldEpochList} epochlist ${epochList}"
	[ -z "$status" ] && status="0"
	eval "l2db_$ipr"=\"${status},${epochList}\"
	l2dbStateChange=1
}

# Args: $1 = IP address
l2dbRemoveRecord () {
	local ipr
	ipr="${1//./_}"
	ipr="${ipr//:/i}"
	eval unset -v \"l2db_$ipr\"
	l2dbStateChange=1
}

# Returns all IPs (not CIDR) present in records
l2dbGetAllIPs () { 
	local ipRaw record
	set | grep -E -e '^l2db_[0-9_]*=' | tr "'" ' ' | while read -r record ; do
	  ipRaw=$(echo "$record" | cut -f1 -d= | sed 's/^l2db_//')
	  if [ "$(echo "${ipRaw//_/ }" | wc -w)" -eq 4 ] ; then
	    echo "${ipRaw//_/.}"
	  fi
	done
	set | grep -E -e '^l2db_[0-9a-fA-Fi]*=' | tr "'" ' ' | while read -r record ; do
	  ipRaw=$(echo "$record" | cut -f1 -d= | sed 's/^l2db_//')
	  echo "${ipRaw//i/:}"
	done
}

# retrieve single IP record, Args: $1=IP
l2dbGetRecord () {
	local record
	record=$(echo "$1" | sed -e 's/\./_/g' -e 's/:/i/g' -e 's/^/l2db_/')
	eval echo \"\$$record\"
}

isValidBindTime () { echo "$1" | grep -E -q -e '^[0-9]+$|^([0-9]+[wdhms]?)+$' ;}

# expands Bind time syntax into seconds (ex: 3w6d23h59m59s), Arg: $1=time string
expandBindTime () {
	isValidBindTime "$1" || { logLine 0 "Error: Invalid time specified ($1)" >&2 ; exit 254 ;}
	echo $(($(echo "$1" | sed -e 's/w+*/*7d+/g' -e 's/d+*/*24h+/g' -e 's/h+*/*60m+/g' -e 's/m+*/*60+/g' \
	  -e 's/s//g' -e 's/+$//')))
}

# Args: $1 = loglevel, $2 = info to log
logLine () {
	[ "$1" -gt "$logLevel" ] && return
	shift
	if [ "$logFacility" = "stdout" ] ; then echo "$@"
	elif [ "$logFacility" = "stderr" ] ; then echo "$@" >&2
	else logger -t "$syslogTag" -p "$logFacility" "$@"
	fi
}

# extra validation, fails safe. Args: $1=log line
getLogTime () {
	local logDateString
	logDateString=$(echo "$1" | sed -n \
	  's/^[A-Z][a-z]* \([A-Z][a-z]*  *[0-9][0-9]*  *[0-9][0-9]*:[0-9][0-9]:[0-9][0-9] [0-9][0-9]*\) .*$/\1/p')
	date -d"$logDateString" -D"$formatLogDate" +%s || logLine 1 "Error: logDateString($logDateString) malformed line ($1)"
}

# extra validation, fails safe. Args: $1=log line
getLogIP4 () { 
	local logLine
	logLine="$1"
	echo "$logLine" | sed -En 's/^.*<(([0-9]{1,3}\.){3}([0-9]{1,3})):[0-9]{1,5}>.*/\1/p'
}

getLogIP6 () {
	local logLine
	logLine="$1"
	echo "$logLine" | sed -En 's/^.*<((:?[0-9a-fA-F]{1,4}:?){1,7}):[0-9]{1,5}>.*/\1/p'
}

getLogIP () {
	local ip
	ip="$(getLogIP4 "$1")"

	if [ -z "$ip" ] ; then
	  ip="$(getLogIP6 "$1")"
	fi
	echo "$ip"
}

# is address ipv4 or ipv6
getIPType () {
	case "$1" in
		*:*) echo "6" ;;
		*.*) echo "4" ;;
		*) echo "" ;;
	esac
}

# Args: $1=IP
unBanIP () {
	local ip iptype ipsetname
	ip="$1"
	iptype=$(getIPType "$ip")
	ipsetname="log2dropset${iptype}"

	if ! ipset test "$ipsetname" "$ip" ; then
	  logLine 1 "Removing ban rule for IP $ip from ipset"
	  ipset del -exist "$ipsetname" "$ip"
	else
	  logLine 3 "unBanIP() $ip not present in ipset"
	fi
}

# Args: $1=IP
banIP () {
	local ip iptype ipsetname
	ip="$1"
	iptype=$(getIPType "$ip")
	ipsetname="log2dropset${iptype}"

	if ! ipset test "$ipsetname" "$ip" ; then
	  logLine 1 "Inserting IP $ip into ipset ${ipsetname}"
	  ipset add -exist "$ipsetname" "$ip"
	else
	  logLine 3 "banIP() $ip already present in ipset"
	fi
}

# review state file for expired records
l2dbCheckStatusAll () {
	local now
	now=$(date +%s)
	l2dbGetAllIPs | while read -r ip ; do
	  ipstatus=$(l2dbGetStatus "$ip")
	  if [ "$ipstatus" -eq 1 ] ; then
	    logLine 3 "l2dbCheckStatusAll($ip) testing banLength:$banLength + l2dbGetTimes:$(l2dbGetTimes "$ip") vs. now:$now"
	    if [ $((banLength + $(l2dbGetTimes "$ip"))) -lt "$now" ] ; then
	      logLine 1 "Ban expired for $ip, removing from ipset"
	      unBanIP "$ip"
	      l2dbRemoveRecord "$ip"
	    else 
	      logLine 3 "l2dbCheckStatusAll($ip) not expired yet"
	      banIP "$ip"
	    fi
	  elif [ "$ipstatus" -eq 0 ] ; then
	    local times timeCount lastTime
	    times=$(l2dbGetTimes "$ip")
	    times="${times//,/ }"
	    timeCount=$(echo "$times" | wc -w)
	    lastTime=$(echo "$times" | cut -d' ' -f"$timeCount")
	    if [ $((lastTime + attemptPeriod)) -lt "$now" ] ; then
	      l2dbRemoveRecord "$ip"
	  fi ; fi
	  saveState "null"
	done
	loadState
}

# Only used when status is already 0 and possibly going to 1, Args: $1=IP
l2dbEvaluateRecord () {
	local ip firstTime lastTime times timeCount didBan
	ip="$1"
	times=$(l2dbGetRecord "$ip" | cut -d, -f2- )
	times="${times//,/ }"
	timeCount=$(echo "$times" | wc -w)
	didBan=0
	
	# 1: not enough attempts => do nothing and exit
	# 2: attempts exceed threshold in time period => ban
	# 3: attempts exceed threshold but time period is too long => trim oldest time, recalculate
	while [ "$timeCount" -ge "$attemptCount" ] ; do
	  firstTime=$(echo "$times" | cut -d' ' -f1)
	  lastTime=$(echo "$times" | cut -d' ' -f"$timeCount")
	  timeDiff=$((lastTime - firstTime))
	  logLine 3 "l2dbEvaluateRecord($ip) count=$timeCount timeDiff=$timeDiff/$attemptPeriod"
	  if [ "$timeDiff" -le "$attemptPeriod" ] ; then
	    l2dbEnableStatus "$ip" "$lastTime"
	    logLine 2 "l2dbEvaluateRecord($ip) exceeded ban threshold, adding to ipset"
	    banIP "$ip"
	    didBan=1
	  fi
	  times=$(echo "$times" | cut -d' ' -f2-)
	  timeCount=$(echo "$times" | wc -w)
	done  
	[ "$didBan" = 0 ] && logLine 2 "l2dbEvaluateRecord($ip) does not exceed threshold, skipping"
}

# Reads filtered log line and evaluates for action  Args: $1=log line
processLogLine () {
	local time ip status
	time=$(getLogTime "$1")
	ip=$(getLogIP "$1")
	status="$(l2dbGetStatus "$ip")"

	if [ "$status" = -1 ] ; then
	  logLine 2 "processLogLine($ip,$time) IP is whitelisted"
	elif [ "$status" = 1 ] ; then
	  if [ "$(l2dbGetTimes "$ip")" -ge "$time" ] ; then
	    logLine 2 "processLogLine($ip,$time) already banned, ban timestamp already equal or newer"
	  else
	    logLine 2 "processLogLine($ip,$time) already banned, updating ban timestamp"
	    l2dbEnableStatus "$ip" "$time"
	  fi
	  banIP "$ip"
	elif [ -n "$ip" -a -n "$time" ] ; then
	  l2dbAddRecord "$ip" "$time"
	  logLine 2 "processLogLine($ip,$time) Added record, comparing"
	  l2dbEvaluateRecord "$ip"
	else
	  logLine 1 "processLogLine($ip,$time) malformed line ($1)"
	fi
}

# Args, $1=-f to force a persistent write (unless lastPersistentStateWrite=-1)
saveState () {
	local forcePersistent
	forcePersistent=0
	[ "$1" = "-f" ] && forcePersistent=1

	if [ "$l2dbStateChange" -gt 0 ] ; then
	  logLine 3 "saveState() saving to temp state file"
	  l2dbSave "$fileStateTempPrefix" "$fileStateType"
	  logLine 3 "saveState() now=$(date +%s) lPSW=$lastPersistentStateWrite pSWP=$persistentStateWritePeriod fP=$forcePersistent"
	fi
	if [ "$persistentStateWritePeriod" -gt 1 ] || [ "$persistentStateWritePeriod" -eq 0 -a "$forcePersistent" -eq 1 ] ; then
	  if [ $(($(date +%s) - lastPersistentStateWrite)) -ge "$persistentStateWritePeriod" ] || [ "$forcePersistent" -eq 1 ] ; then
	    if [ ! -f "$fileStatePersist" ] || ! cmp -s "$fileStateTemp" "$fileStatePersist" ; then
	      logLine 2 "saveState() writing to persistent state file"
	      l2dbSave "$fileStatePersistPrefix" "$fileStateType"
	      lastPersistentStateWrite="$(date +%s)"
	fi ; fi ; fi
}

loadState () {
	l2dbClear
	[ "$1" = "-f" ] && l2dbLoad "$fileStatePersistPrefix" "$fileStateType"
	l2dbLoad "$fileStateTempPrefix" "$fileStateType"
	logLine 2 "loadState() loaded $(l2dbCount) entries"
}

printUsage () {
	cat <<-_EOF_
	Usage: log2drop [-m mode] [-a #] [-b #] [-c ...] [-C ...] [-f ...] [-l #] [-j ...] [-p #] [-P #] [-s ...]

	  Running Modes (-m) (def: $defaultMode)
	    follow     constantly monitors log
	    entire     processes entire log contents
	    today      processes log entries from same day only
	    #          interval mode, specify time string or seconds
	    wipe       wipe state files, unhook and remove firewall chain

	  Options
	    -a #   attempt count before banning (def: $attemptCount)
	    -b #   ban length once attempts hit threshold (def: $banLength)
	    -c ... firewall chain to record bans (def: $firewallChain)
	    -f ... log facility (syslog facility or stdout/stderr) (def: $logFacility)
	    -j ... firewall target (def: $firewallTarget)
	    -l #   log level - 0=off, 1=standard, 2=verbose (def: $logLevel)
	    -p #   attempt period which attempt counts must happen in (def: $attemptPeriod)
	    -P #   persistent state file write period (def: $persistentStateWritePeriod)
	    -s ... persistent state file prefix (def: $fileStatePersistPrefix)
	    -t ... temporary state file prefix (def: $fileStateTempPrefix)

	  All time strings can be specified in seconds, or using BIND style
	  time strings, ex: 1w2d3h5m30s is 1 week, 2 days, 3 hours, etc...

_EOF_
}

#  Begin main logic
#
while getopts a:b:f:l:p:P:s:t: arg ; do
	case "$arg" in 
	  a) attemptCount="$OPTARG" ;;
	  b) banLength="$OPTARG" ;;
	  f) logFacility="$OPTARG" ;;
	  l) logLevel="$OPTARG" ;;
	  p) attemptPeriod="$OPTARG" ;;
	  P) persistentStateWritePeriod="$OPTARG" ;;
	  s) fileStatePersistPrefix="$OPTARG" ;;
	  *) printUsage
	    exit 254
	esac
	shift $((OPTIND - 1))
done

fileStateTemp="$fileStateTempPrefix.$fileStateType"
fileStatePersist="$fileStatePersistPrefix.$fileStateType"

attemptPeriod=$(expandBindTime "$attemptPeriod")
banLength=$(expandBindTime "$banLength")
[ "$persistentStateWritePeriod" != -1 ] && persistentStateWritePeriod=$(expandBindTime "$persistentStateWritePeriod")
followModeCheckInterval=$(expandBindTime "$followModeCheckInterval")
exitStatus=0

# Here we convert the logRegex list into a sed -f file
fileRegex="/tmp/log2drop.$$.regex"
uciLoad logRegex > "$fileRegex"
lastPersistentStateWrite="$(date +%s)"
loadState -f
l2dbCheckStatusAll

# main event loops
logLine 1 "Running in follow mode"
readsSinceSave=0 lastCheckAll=0 worstCaseReads=1 tmpFile="/tmp/log2drop.$$.1"
trap "rm -f \"\$tmpFile\" \"\$fileRegex\" ; exit " SIGINT
[ "$persistentStateWritePeriod" -gt 1 ] && worstCaseReads=$((persistentStateWritePeriod / followModeCheckInterval))
firstRun=1
"$cmdLogread" -f | while read -r -t "$followModeCheckInterval" rawline || true ; do
	if [ "$firstRun" -eq 1 ] ; then
		trap "saveState -f" SIGHUP
		trap "saveState -f; rm -f \"\$tmpFile\" \"\$fileRegex\" ; exit" SIGINT
		firstRun=0
	fi
	line="$(echo -n "$rawline" | sed -nEf "$fileRegex")"
	[ -n "$line" ] && processLogLine "$line"
	logLine 4 "ReadComp:$readsSinceSave/$worstCaseReads"
	if [ $((++readsSinceSave)) -ge "$worstCaseReads" ] ; then
		now="$(date +%s)"
		if [ $((now - lastCheckAll)) -ge "$followModeCheckInterval" ] ; then
			l2dbCheckStatusAll
			lastCheckAll="$now"
			saveState "null"
			readsSinceSave=0
		fi
	fi
done

rm -f "$fileRegex"
exit "$exitStatus"
