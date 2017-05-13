#!/bin/ash

. /usr/share/libubox/jshn.sh

PROTOCOL=0.1

_log() {
  local level=$1
  shift
  logger -s -t openwifi -p daemon.$level $@
}


# register a device to the controller
device_register() {
  local server=$1
  local port=$2
  local path=$3
  local uuid=$4
  local useSSL=$5
  local hostname=$(uci get system.@system[0].hostname)
  local address
  local protocol

  if [ "$useSSL" = "useSSL" ]; then
      protocol="https"
  else
      protocol="http"
  fi

  address=$(nslookup "$server" 2>/dev/null | tail -n1 | awk '{print $3}')
  if [ -z "$address" ] ; then
    _log error "Could not find server"
    return 1
  fi

  . /etc/openwrt_release

  localaddress=$(ip r g "${address}" | head -n1 | sed "s/.*src\s*//g")
  user=root
  password="$(dd if=/dev/urandom bs=512 count=1 2>/dev/null | md5sum - | cut -c1-16)"

  rm /etc/*lock #Remove lock files - TODO findout why is is necessary!
  useradd generatepw
  echo -e "$password\n$password\n" | passwd generatepw

  uci set rpcd.@login[0].password="\$p\$generatepw"
  uci commit rpcd
  _log info "Registering to server $server"

  wget --no-check-certificate -q -O/dev/null \
      --header='Content-Type: application/json' \
      --post-data="\
        {\"params\": \
          { \"uuid\":\"${uuid}\", \
            \"name\": \"${hostname}\", \
            \"address\": \"${localaddress}\", \
            \"distribution\": \"${DISTRIB_ID}\", \
            \"version\": \"${DISTRIB_RELEASE}\", \
            \"proto\": \"${PROTOCOL}\", \
            \"login\": \"${user}\", \
            \"password\": \"${password}\" \
            }, \
        \"method\": \"device_register\", \
        \"jsonrpc\": \"2.0\" }" \
        "${protocol}://${address}:${port}${path}/api"
  return $?
}

# check if device is already registered
device_is_registered() {
  local server="$1"
  local port="$2"
  local path="$3"
  local uuid="$4"
  local useSSL="$5"

  if [ "$useSSL" = "useSSL" ]; then
      protocol="https"
  else
      protocol="http"
  fi

  RESPONSE=$(wget --no-check-certificate -q -O- \
      --header='Content-Type: application/json' \
      --post-data="\
        {\"params\": \
          { \
            \"uuid\":\"${uuid}\", \
            \"name\":\"\" \
          }, \
        \"method\": \"device_check_registered\", \
        \"jsonrpc\": \"2.0\" }" \
      "${protocol}://${server}:${port}${path}/api")

  json_load "$RESPONSE"
  json_get_var result result

  if [ "$result" = "yes" ] ; then
    return 0;
  else
    return 1;
  fi
}

# check if server $1 is a openwifi server
device_discover_server() {
  local server="$1"
  local port="$2"
  local path="$3"
  local useSSL="$4"
  local result
  local protocol

  if [ "$useSSL" = "useSSL" ]; then
     protocol="https"
  else
     protocol="http"
  fi


  RESPONSE=$(wget --no-check-certificate -q -O- \
      --header='Content-Type: application/json' \
      --post-data="\
        {\"params\": \
          { \
          }, \
        \"id\": \"23\", \
        \"method\": \"hello\", \
        \"jsonrpc\": \"2.0\" }" \
      "${protocol}://${server}:${port}${path}/api")
  json_load "$RESPONSE"

  if [ $? -ne 0 ]; then
      return 1
  fi

  json_get_var result result
  if [ "$result" = "openwifi" ] ; then
    return 0
  fi

  return 1
}

# search for a openwifi controller and set it if found
device_discover() {
  local register=$1
  if device_discover_server "openwifi" "80" ; then
    set_controller "openwifi" "80" "" "$register"
    return 0
  fi

  # check if umdns is available
  if ubus list umdns ; then
    local umdns entries ip
    ubus call umdns update
    umdns=$(ubus call umdns browse)

    entries=$(jsonfilter -s "$umdns" -e '$["_openwifi._tcp"][*]')
    entries=$(echo $entries|sed s/\ //g|sed s/\}/}\ /g)
    for entry in $entries ; do
        ip=$(jsonfilter -s "$entry" -e '$["ipv4"]')
        path=$(jsonfilter -s "$entry" -e '$["txt"]'|sed 's/path=\([^;]*\).*/\1/')
        useSSL=$(jsonfilter -s "$entry" -e '$["txt"]'|grep -o useSSL)
        port=$(jsonfilter -s "$entry" -e '$["port"]')
        if device_discover_server "$ip" "$port" "$path" "$useSSL"; then
            set_controller "$ip" "$port" "$path" "$register" "$useSSL"
            return 0
        fi
    done
  else # use avahi as fallback
    local entries ip path port txt
    entries=$(avahi-browse -rcp _openwifi._tcp|grep =|grep IPv4)
    for entry in $entries ; do
        ip=$(echo "$entry" | awk -F";" '{print$8}')
        port=$(echo "$entry" | awk -F";" '{print $9}')
        txt=$(echo "$entry" | awk -F";" '{print $10}')
        path=$(echo "$txt" | sed 's/path=\([^;]*\).*/\1/' | sed s/\"//g)
        useSSL=$(echo "$txt"|grep -o useSSL)
        if device_discover_server "$ip" "$port" "$path" "$useSSL" ; then
            set_controller "$ip" "$port" "$path" "$register" "$useSSL"
            return 0
        fi
    done
  fi

  return 1
}

device_generate_uuid() {
  local uuid=""

  # Random UUID
  #uuid=$(cat /proc/sys/kernel/random/uuid)
  #if [ -z "$uuid" ] ; then
  #  return 1
  #fi


  #ID Based on CPU and eth0

  local CPU_MD5=$(egrep "vendor|family|model|flags" /proc/cpuinfo | md5sum | sed "s/\s*-\s*//g")
  local ETH0_MAC_WITHOUT_COLONS=$(sed "s/://g" /sys/class/net/eth0/address)
  uuid=${CPU_MD5:0:8}-${CPU_MD5:8:4}-${CPU_MD5:12:4}-${CPU_MD5:16:4}-$ETH0_MAC_WITHOUT_COLONS

  uci set openwifi.@device[0].uuid="$uuid"
  uci commit openwifi
  return 0
}

# try to set the controller and register to it
set_controller() {
  local server=$1
  local port=$2
  local path=$3
  local uuid=$(uci get openwifi.@device[0].uuid)
  local register=$4
  local useSSL=$5

  if [ "$register" != "doNotRegister" ]  ; then
          if ! device_register "$server" "$port" "$path" "$uuid" "$useSSL" ; then
            return 1
          fi
  fi

  uci delete openwifi.@server[]
  uci add openwifi server
  uci set openwifi.@server[0].address="$server"
  uci set openwifi.@server[0].port="$port"
  uci set openwifi.@server[0].path="$path"
  uci set openwifi.@server[0].useSSL="$useSSL"
  uci commit openwifi
  return 0
}

openwifi() {
  local server port path useSSL
  local uuid
  local i=0

  while [ $i -lt 3 ] ; do
    server=$(uci get openwifi.@server[0].address)
    port=$(uci get openwifi.@server[0].port)
    useSSL=$(uci get openwifi.@server[0].useSSL)
    path=$(uci get openwifi.@server[0].path)
    uuid=$(uci get openwifi.@device[0].uuid)

    # check if a uuid was generated
    if [ -z "$uuid" ] ; then
      if ! device_generate_uuid ; then
        _log error "Could not generate a uuid"
        continue
      fi
      uuid=$(uci get openwifi.@device[0].uuid)
    fi

    if [ -z "$server" ] ; then
      if ! device_discover ; then
        _log error "Could not discover a server"
        continue
      fi
      server=$(uci get openwifi.@server[0].address)
      port=$(uci get openwifi.@server[0].port)
      path=$(uci get openwifi.@server[0].path)
      useSSL=$(uci get openwifi.@server[0].useSSL)
    fi

    # check if server is reachable
    if ! device_discover_server "$server" "$port" "$path" "$useSSL"; then
      _log error "Server $server does not respond! Clear old server"
      uci delete openwifi.@server[]
      uci commit openwifi
      continue
    fi

    if ! device_is_registered "$server" "$port" "$path" "$uuid" "$useSSL"; then
      device_register "$server" "$port" "$path" "$uuid" "$useSSL" && return 0
    else
      return 0
    fi
    i=$((i + 1))
    sleep 3
  done
  _log error "Could not find a suitable server or server doesn't repond"
  return 1
}
