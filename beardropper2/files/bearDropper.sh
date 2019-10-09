#!/bin/ash
#
# bearDropper - dropbear log parsing ban agent for OpenWRT (Chaos Calmer rewrite of dropBrute.sh)
#   http://github.com/robzr/bearDropper  -- Rob Zwissler 11/2015
# 
#   - lightweight, no dependencies, busybox ash + native OpenWRT commands
#   - uses uci for configuration, overrideable via command line arguments
#   - runs continuously in background (via init script) or periodically (via cron)
#   - uses BIND time shorthand, ex: 1w5d3h1m8s is 1 week, 5 days, 3 hours, 1 minute, 8 seconds
#   - Whitelist IP or CIDR entries (TBD) in uci config file
#   - Records state file to tmpfs and intelligently syncs to persistent storage (can disable)
#   - Persistent sync routines are optimized to avoid excessive writes (persistentStateWritePeriod)
#   - Every run occurs in one of the following modes. If not specified, interval mode (24 hours) is 
#     the default when not specified (the init script specifies follow mode via command line)
# 
#     "follow" mode follows syslog to process entries as they happen; generally launched via init
#        script. Responds the fastest, runs the most efficiently, but is always in memory.

# Load UCI config variable, or use default if not set
# Args: $1 = variable name (also uci option name), $2 = default_value
uciSection='bearDropper.@[0]'
uciLoadVar () { 
	local getUci
	getUci=`uci -q get ${uciSection}."$1"` || getUci="$2" 
	eval $1=\'$getUci\'; 
}
uciLoad() {
	local tFile=`mktemp` delim="
"
	[ "$1" = -d ] && { delim="$2"; shift 2; }
	uci -q -d"$delim" get "$uciSection.$1" 2>/dev/null >$tFile
	if [ $? = 0 ] ; then
	  sed -e s/^\'// -e s/\'$// <$tFile
	else
	  while [ -n "$2" ]; do echo $2; shift; done
	fi
	rm -f $tFile
}

# Common config variables - edit these in /etc/config/bearDropper
# or they can be overridden at runtime with command line options
#
uciLoadVar defaultMode entire
uciLoadVar attemptCount 10
uciLoadVar attemptPeriod 12h
uciLoadVar banLength 1w
uciLoadVar logLevel 1
uciLoadVar logFacility authpriv.notice
uciLoadVar persistentStateWritePeriod -1
uciLoadVar fileStateType bddb
uciLoadVar fileStateTempPrefix /tmp/bearDropper
uciLoadVar fileStatePersistPrefix /etc/bearDropper
uciLoadVar firewallTarget DROP

# Not commonly changed, but changeable via uci or cmdline (primarily 
# to enable multiple parallel runs with different parameters)
uciLoadVar firewallChain bearDropper

# Advanced variables, changeable via uci only (no cmdline), it is 
# unlikely that these will need to be changed, but just in case...
#
uciLoadVar syslogTag "bearDropper[$$]"
# how often to attempt to expire bans when in follow mode
uciLoadVar followModeCheckInterval 30m
uciLoadVar cmdLogread 'logread'		# for tuning, ex: "logread -l250"
uciLoadVar formatLogDate '%b %e %H:%M:%S %Y'	# used to convert syslog dates
uciLoadVar formatTodayLogDateRegex '^%a %b %e ..:..:.. %Y'	# filter for today mode

# Begin functions
#
# Clear bddb entries from environment
bddbClear () { 
	local bddbVar
	for bddbVar in `set | egrep '^bddb[46]_[0-9a-fA-F_]*=' | cut -f1 -d= | xargs echo -n` ; do eval unset $bddbVar ; done
	bddbStateChange=1
}

# Returns count of unique IP entries in environment
bddbCount () { set | egrep '^bddb[46]_[0-9a-fA-F_]*=' | wc -l ;}

# Loads existing bddb file into environment
# Arg: $1 = file, $2 = type (bddb/bddbz)
bddbLoad () { 
	local loadFile="$1.$2" fileType="$2"
	if [ "$fileType" = bddb -a -f "$loadFile" ] ; then
	  . "$loadFile"
	elif [ "$fileType" = bddbz -a -f "$loadFile" ] ; then
	  local tmpFile="`mktemp`"
	  zcat $loadFile > "$tmpFile"
	  . "$tmpFile"
	  rm -f "$tmpFile"
	fi
	bddbStateChange=0
}

# Saves environment bddb entries to file, Arg: $1 = file to save in
bddbSave () { 
	local saveFile="$1.$2" fileType="$2"
	if [ "$fileType" = bddb ] ; then
	  set | egrep '^bddb[46]_[0-9a-fA-F_]*=' | sed s/\'//g > "$saveFile"
	elif [ "$fileType" = bddbz ] ; then
	  set | egrep '^bddb[46]_[0-9a-fA-F_]*=' | sed s/\'//g | gzip -c > "$saveFile"
	fi
	bddbStateChange=0 
}

# Set bddb record status=1, update ban time flag with newest
# Args: $1=IP Address $2=timeFlag
bddbEnableStatus () {
	local iptype=$(getIPType "$1")
	if [ "$iptype" = 4 ] ; then
	  local record=`echo $1 | sed -e 's/\./_/g' -e 's/^/bddb4_/'`
	else
	  local record=`echo $1 | sed -e 's/\:/_/g' -e 's/^/bddb6_/'`
	fi
	local newestTime=`bddbGetTimes $1 | sed 's/.* //' | xargs echo $2 | tr \  '\n' | sort -n | tail -1 `
	eval $record="1,$newestTime"
	bddbStateChange=1
}

# Args: $1=IP Address
bddbGetStatus () {
	bddbGetRecord $1 | cut -d, -f1
}

# Args: $1=IP Address
bddbGetTimes () {
	bddbGetRecord $1 | cut -d, -f2-
}

# Args: $1 = IP , $2 [$3 ...] = timestamp (seconds since epoch)
bddbAddRecord () {
	local iptype=$(getIPType "$1")
	local ip="`echo "$1" | tr .: __`" ; shift
	local newEpochList="$@" status="`eval echo \\\$bddb${iptype}_$ip | cut -f1 -d,`"
	local oldEpochList="`eval echo \\\$bddb${iptype}_$ip | cut -f2- -d,  | tr , \ `" 
	local epochList=`echo $oldEpochList $newEpochList | xargs -n 1 echo | sort -un | xargs echo -n | tr \  ,`
	[ -z "$status" ] && status=0
	eval "bddb${iptype}_$ip"\=\"$status,$epochList\"
	bddbStateChange=1
}

# Args: $1 = IP address
bddbRemoveRecord () {
	local iptype=$(getIPType "$1")
	local ip="`echo "$1" | tr .: __`"
	eval unset bddb${iptype}_$ip
	bddbStateChange=1
}

# Returns all IPs (not CIDR) present in records
bddbGetAllIPs () { 
	local ipRaw record
	set | egrep '^bddb4_[0-9_]*=' | tr \' \  | while read record ; do
	  ipRaw=`echo $record | cut -f1 -d= | sed 's/^bddb4_//'`
	  if [ `echo $ipRaw | tr _ \  | wc -w` -eq 4 ] ; then
	    echo $ipRaw | tr _ .
	  fi
	done
	set | egrep '^bddb6_[0-9a-fA-F_]*=' | tr \' \  | while read record ; do
	  ipRaw=`echo $record | cut -f1 -d= | sed 's/^bddb6_//'`
	  echo $ipRaw | tr _ :
	done
}

# retrieve single IP record, Args: $1=IP
bddbGetRecord () {
	local record
	local iptype=$(getIPType "$1")
	if [ 4 = "$iptype" ] ; then
	  record=`echo $1 | sed -e 's/\./_/g' -e 's/^/bddb4_/'`
	else
	  record=`echo $1 | sed -e 's/\:/_/g' -e 's/^/bddb6_/'`
	fi
	eval echo \$$record
}

isValidBindTime () { echo "$1" | egrep -q '^[0-9]+$|^([0-9]+[wdhms]?)+$' ; }

# expands Bind time syntax into seconds (ex: 3w6d23h59m59s), Arg: $1=time string
expandBindTime () {
	isValidBindTime "$1" || { logLine 0 "Error: Invalid time specified ($1)" >&2 ; exit 254 ; }
	echo $((`echo "$1" | sed -e 's/w+*/*7d+/g' -e 's/d+*/*24h+/g' -e 's/h+*/*60m+/g' -e 's/m+*/*60+/g' \
	  -e s/s//g -e s/+\$//`))
}

# Args: $1 = loglevel, $2 = info to log
logLine () {
	[ $1 -gt $logLevel ] && return
	shift
	if [ "$logFacility" = "stdout" ] ; then echo "$@"
	elif [ "$logFacility" = "stderr" ] ; then echo "$@" >&2
	else logger -t "$syslogTag" -p "$logFacility" "$@"
	fi
}

# extra validation, fails safe. Args: $1=log line
getLogTime () {
	local logDateString=`echo "$1" | sed -n \
	  's/^[A-Z][a-z]* \([A-Z][a-z]*  *[0-9][0-9]*  *[0-9][0-9]*:[0-9][0-9]:[0-9][0-9] [0-9][0-9]*\) .*$/\1/p'`
	date -d"$logDateString" -D"$formatLogDate" +%s || logLine 1 \
	  "Error: logDateString($logDateString) malformed line ($1)"
}

# extra validation, fails safe. Args: $1=log line
getLogIP4 () { 
	local logLine="$1"
	echo "$logLine" | sed -En 's/^.*<(([0-9]{1,3}\.){3}([0-9]{1,3})):[0-9]{1,5}>.*/\1/p'
}

getLogIP6 () {
	local logLine="$1"
	echo "$logLine" | sed -En 's/^.*<((:?[0-9a-fA-F]{1,4}:?){1,7}):[0-9]{1,5}>.*/\1/p'
}

getLogIP () {
	local ip="$(getLogIP4 "$1")"

	if [ -z "$ip" ] ; then
	  ip="$(getLogIP6 "$1")"
	fi
	echo "$ip"
}

# is address ipv4 or ipv6
getIPType () {
	case $1 in
		*:*) echo "6" ;;
		*.*) echo "4" ;;
		*) echo "0" ;;
	esac
}

# Args: $1=IP
unBanIP () {
	local ip="$1"
	local iptype=$(getIPType "$ip")
	local ipsetname="beardropperset${iptype}"

	if ! ipset test "$ipsetname" "$ip" ; then
	  logLine 1 "Removing ban rule for IP $ip from ipset"
	  ipset del -exist "$ipsetname" "$ip"
	else
	  logLine 3 "unBanIP() $ip not present in ipset"
	fi
}

# Args: $1=IP
banIP () {
	local ip="$1"
	local iptype=$(getIPType "$ip")
	local ipsetname="beardropperset${iptype}"

	if ! ipset test "$ipsetname" "$ip" ; then
	  logLine 1 "Inserting IP $ip into ipset ${ipsetname}"
	  ipset add -exist "$ipsetname" "$ip"
	else
	  logLine 3 "banIP() $ip already present in ipset"
	fi
}

# review state file for expired records
bddbCheckStatusAll () {
	local now=`date +%s`
	bddbGetAllIPs | while read ip ; do
	  ipstatus=$(bddbGetStatus $ip)
	  if [ $ipstatus -eq 1 ] ; then
	    logLine 3 "bddbCheckStatusAll($ip) testing banLength:$banLength + bddbGetTimes:`bddbGetTimes $ip` vs. now:$now"
	    if [ $((banLength + `bddbGetTimes $ip`)) -lt $now ] ; then
	      logLine 1 "Ban expired for $ip, removing from ipset"
	      unBanIP $ip
	      bddbRemoveRecord $ip
	    else 
	      logLine 3 "bddbCheckStatusAll($ip) not expired yet"
	      banIP $ip
	    fi
	  elif [ $ipstatus -eq 0 ] ; then
	    local times=`bddbGetTimes $ip | tr , \ `
	    local timeCount=`echo $times | wc -w`
	    local lastTime=`echo $times | cut -d\  -f$timeCount`
	    if [ $((lastTime + attemptPeriod)) -lt $now ] ; then
	      bddbRemoveRecord $ip
	  fi ; fi
	  saveState
	done
	loadState
}

# Only used when status is already 0 and possibly going to 1, Args: $1=IP
bddbEvaluateRecord () {
	local ip=$1 firstTime lastTime
	local times=`bddbGetRecord $1 | cut -d, -f2- | tr , \ `
	local timeCount=`echo $times | wc -w`
	local didBan=0
	
	# 1: not enough attempts => do nothing and exit
	# 2: attempts exceed threshold in time period => ban
	# 3: attempts exceed threshold but time period is too long => trim oldest time, recalculate
	while [ $timeCount -ge $attemptCount ] ; do
	  firstTime=`echo $times | cut -d\  -f1`
	  lastTime=`echo $times | cut -d\  -f$timeCount`
	  timeDiff=$((lastTime - firstTime))
	  logLine 3 "bddbEvaluateRecord($ip) count=$timeCount timeDiff=$timeDiff/$attemptPeriod"
	  if [ $timeDiff -le $attemptPeriod ] ; then
	    bddbEnableStatus $ip $lastTime
	    logLine 2 "bddbEvaluateRecord($ip) exceeded ban threshold, adding to ipset"
	    banIP $ip
	    didBan=1
	  fi
	  times=`echo $times | cut -d\  -f2-`
	  timeCount=`echo $times | wc -w`
	done  
	[ $didBan = 0 ] && logLine 2 "bddbEvaluateRecord($ip) does not exceed threshhold, skipping"
}

# Reads filtered log line and evaluates for action  Args: $1=log line
processLogLine () {
	local time=`getLogTime "$1"` 
	local ip=$(getLogIP "$1")
	local status="`bddbGetStatus $ip`"

	if [ "$status" = -1 ] ; then
	  logLine 2 "processLogLine($ip,$time) IP is whitelisted"
	elif [ "$status" = 1 ] ; then
	  if [ "`bddbGetTimes $ip`" -ge $time ] ; then
	    logLine 2 "processLogLine($ip,$time) already banned, ban timestamp already equal or newer"
	  else
	    logLine 2 "processLogLine($ip,$time) already banned, updating ban timestamp"
	    bddbEnableStatus $ip $time
	  fi
	  banIP "$ip"
	elif [ -n "$ip" -a -n "$time" ] ; then
	  bddbAddRecord $ip $time
	  logLine 2 "processLogLine($ip,$time) Added record, comparing"
	  bddbEvaluateRecord $ip
	else
	  logLine 1 "processLogLine($ip,$time) malformed line ($1)"
	fi
}

# Args, $1=-f to force a persistent write (unless lastPersistentStateWrite=-1)
saveState () {
	local forcePersistent=0
	[ "$1" = "-f" ] && forcePersistent=1

	if [ $bddbStateChange -gt 0 ] ; then
	  logLine 3 "saveState() saving to temp state file"
	  bddbSave "$fileStateTempPrefix" "$fileStateType"
	  logLine 3 "saveState() now=`date +%s` lPSW=$lastPersistentStateWrite pSWP=$persistentStateWritePeriod fP=$forcePersistent"
	fi    
	if [ $persistentStateWritePeriod -gt 1 ] || [ $persistentStateWritePeriod -eq 0 -a $forcePersistent -eq 1 ] ; then
	  if [ $((`date +%s` - lastPersistentStateWrite)) -ge $persistentStateWritePeriod ] || [ $forcePersistent -eq 1 ] ; then
	    if [ ! -f "$fileStatePersist" ] || ! cmp -s "$fileStateTemp" "$fileStatePersist" ; then
	      logLine 2 "saveState() writing to persistent state file"
	      bddbSave "$fileStatePersistPrefix" "$fileStateType"
	      lastPersistentStateWrite="`date +%s`"
	fi ; fi ; fi
}

loadState () {
	bddbClear
	[ "$1" = "-f" ] && bddbLoad "$fileStatePersistPrefix" "$fileStateType"
	bddbLoad "$fileStateTempPrefix" "$fileStateType"
	logLine 2 "loadState() loaded `bddbCount` entries"
}

printUsage () {
	cat <<-_EOF_
	Usage: bearDropper [-m mode] [-a #] [-b #] [-c ...] [-C ...] [-f ...] [-l #] [-j ...] [-p #] [-P #] [-s ...]

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
unset logMode
while getopts a:b:c:f:hj:l:m:p:P:s:t: arg ; do
	case "$arg" in 
	  a) attemptCount="$OPTARG" ;;
	  b) banLength="$OPTARG" ;;
	  c) firewallChain="$OPTARG" ;;
	  f) logFacility="$OPTARG" ;;
	  j) firewallTarget="$OPTARG" ;;
	  l) logLevel="$OPTARG" ;;
	  m) logMode="$OPTARG" ;;
	  p) attemptPeriod="$OPTARG" ;;
	  P) persistentStateWritePeriod="$OPTARG" ;;
	  s) fileStatePersistPrefix="$OPTARG" ;;
	  s) fileStatePersistPrefix="$OPTARG" ;;
	  *) printUsage
	    exit 254
	esac
	shift `expr $OPTIND - 1`
done
[ -z $logMode ] && logMode="$defaultMode"

fileStateTemp="$fileStateTempPrefix.$fileStateType"
fileStatePersist="$fileStatePersistPrefix.$fileStateType"

attemptPeriod=`expandBindTime $attemptPeriod`
banLength=`expandBindTime $banLength`
[ $persistentStateWritePeriod != -1 ] && persistentStateWritePeriod=`expandBindTime $persistentStateWritePeriod`
followModeCheckInterval=`expandBindTime $followModeCheckInterval`
exitStatus=0

# Here we convert the logRegex list into a sed -f file
fileRegex="/tmp/bearDropper.$$.regex"
uciLoad logRegex > "$fileRegex"
lastPersistentStateWrite="`date +%s`"
loadState -f
bddbCheckStatusAll

# main event loops
if [ "$logMode" = follow ] ; then 
	logLine 1 "Running in follow mode"
	readsSinceSave=0 lastCheckAll=0 worstCaseReads=1 tmpFile="/tmp/bearDropper.$$.1"
# Verify if these do any good - try saving to a temp.  Scope may make saveState useless.
	trap "rm -f "$tmpFile" "$fileRegex" ; exit " SIGINT
	[ $persistentStateWritePeriod -gt 1 ] && worstCaseReads=$((persistentStateWritePeriod / followModeCheckInterval))
	firstRun=1
	$cmdLogread -f | while read -t $followModeCheckInterval line || true ; do
	  if [ $firstRun -eq 1 ] ; then
	    trap "saveState -f" SIGHUP
	    trap "saveState -f; exit" SIGINT
	    firstRun=0
	  fi
	  sed -nEf "$fileRegex" > "$tmpFile" <<-_EOF_
	$line
	_EOF_
	  line="`cat $tmpFile`"
	  [ -n "$line" ] && processLogLine "$line"
	  logLine 4 "ReadComp:$readsSinceSave/$worstCaseReads"
	  if [ $((++readsSinceSave)) -ge $worstCaseReads ] ; then
	    now="`date +%s`"
	    if [ $((now - lastCheckAll)) -ge $followModeCheckInterval ] ; then
	      bddbCheckStatusAll
	      lastCheckAll="$now"
	      saveState
	      readsSinceSave=0
	    fi
	  fi
	done
fi

rm -f "$fileRegex"
exit $exitStatus
