. /usr/share/libubox/jshn.sh

PROTOCOL=0.1

SERVER=$(uci get openwifi.@server[0].address)
PORT=$(uci get openwifi.@server[0].port)
SSL=$(uci get openwifi.@server[0].useSSL)
WEB_ROOT=$(uci get openwifi.@server[0].path)
UUID=$(uci get openwifi.@device[0].uuid)
HOSTNAME=$(uci get system.@system[0].hostname)
USER="root"
PASSWORD=$(dd if=/dev/urandom bs=512 count=1 2>/dev/null | md5sum - | cut -c1-16)
PASSWD_COMMAND="passwd"
# this contains the information for the server how the node should be contacted
COMMUNICATION_PROTOCOL=$(if netstat -tulpn|grep 0.0.0.0:443|grep -q uhttpd;then echo JSONUBUS_HTTPS; else echo JSONUBUS_HTTP; fi)
CLIENT_CERTS=""

SLEEP=180 # TODO Fix this
. /etc/openwrt_release

_log() {
  local level=$1
  shift
  logger -s -t openwifi -p daemon.$level $@
}

_preinit() {
  # check for command and set as environment
  wget --version &> /dev/null
  if [ $? -ne 0 ]; then
      _log error "no full wget installed"
      return 11
  fi

  # if it is not he busybox passwd
  $PASSWD_COMMAND -h &> /dev/null
  if [ $? -ne 1 ]; then
      if [ /bin/busybox passwd -eq ]; then
          PASSWD_COMMAND="/bin/busybox passwd"
      else
          _log error "not the busybox passwd"
          return 4
      fi
  fi

  if [ -f /etc/openwifi/client.key ] && [ -f /etc/openwifi/client.crt ]; then
      CLIENT_CERTS="--private-key=/etc/openwifi/client.key --certificate=/etc/openwifi/client.crt"
  fi
}

_preinit

_post() {
    local request=$1

    local address=$(nslookup "$SERVER" 2>/dev/null | tail -n1 | awk '{print $3}')
    if [ -z "$address" ] ; then
      _log error "Could not find server IP"
      return 5
    fi

    local localaddress=$(ip r g "${address}" | head -n1 | sed -r "s/.*src ([0-9,\.]*).*/\1/g")

    if [ -n "$SSL" ]; then
         protocol="https"
    else
         protocol="http"
    fi

    #send command as POST
    case $request in
    hello)
      response=$(wget --no-check-certificate -q -O- \
          --header='Content-Type: application/json' \
          ${CLIENT_CERTS} \
          --post-data="\
            {\"params\": \
              { \
              }, \
            \"id\": \"23\", \
            \"method\": \"hello\", \
            \"jsonrpc\": \"2.0\" }" \
          "${protocol}://${SERVER}:${PORT}${WEB_ROOT}/api")
    echo "$response"
    return
    ;;
    device_register)
      wget --no-check-certificate -q -O/dev/null \
          ${CLIENT_CERTS} \
          --header='Content-Type: application/json' \
          --post-data="\
            {\"params\": \
              { \"uuid\":\"${UUID}\", \
                \"name\": \"${HOSTNAME}\", \
                \"address\": \"${localaddress}\", \
                \"distribution\": \"${DISTRIB_ID}\", \
                \"version\": \"${DISTRIB_RELEASE}\", \
                \"proto\": \"${PROTOCOL}\", \
                \"login\": \"${USER}\", \
                \"password\": \"${PASSWORD}\", \
                \"communication_protocol\": \"${COMMUNICATION_PROTOCOL}\" \
                }, \
            \"method\": \"device_register\", \
            \"jsonrpc\": \"2.0\" }" \
            "${protocol}://${address}:${PORT}${WEB_ROOT}/api"
      return $?
    ;;
    device_check_registered)
      response="$(wget --no-check-certificate -q -O- \
          ${CLIENT_CERTS} \
          --header='Content-Type: application/json' \
          --post-data="\
            {\"params\": \
              { \
                \"uuid\":\"${UUID}\", \
                \"name\":\"\" \
              }, \
            \"method\": \"device_check_registered\", \
            \"jsonrpc\": \"2.0\" }" \
          "${protocol}://${SERVER}:${PORT}${WEB_ROOT}/api")"
      echo "$response"
      return
    ;;
    *)
        echo "Unkown Call Command to Configuration Server"
        exit 1
    ;;
    esac
}

# register a device to the controller
device_register() {
  useradd openwifi
  echo -e "$PASSWORD\n$PASSWORD\n" | $PASSWD_COMMAND openwifi

  uci set rpcd.@login[0].password="\$p\$openwifi"
  uci commit rpcd
  _log info "Registering to server $SERVER"

  _post device_register
  return $?
}

# check if device is already registered
device_is_registered() {
  RESPONSE=$(_post device_is_registered)

  json_load "$RESPONSE"
  json_get_var result result

  if [ "$result" = "yes" ] ; then
    return 0;
  else
    return 6;
  fi
}

# check if server $1 is a openwifi server
device_discover_server() {
  RESPONSE=$(_post hello)
  json_load "$RESPONSE"

  if [ $? -ne 0 ]; then
      return 7
  fi

  json_get_var result result

  if [ "$result" = "openwifi" ] ; then
    return 0
  fi

  return 8
}

_umdns_discovery() {
    local umdns entries port

    ubus call umdns update
    umdns=$(ubus call umdns browse)

    entries=$(jsonfilter -s "$umdns" -e '$["_openwifi._tcp"][*]')
    entries=$(echo $entries|sed s/\ //g|sed s/\}/}\ /g)
    for entry in $entries ; do

        SERVER=$(jsonfilter -s "$entry" -e '$["ipv4"]')
        WEB_ROOT=$(jsonfilter -s "$entry" -e '$["txt"]'|sed 's/path=\([^;]*\).*/\1/')
        SSL=$(jsonfilter -s "$entry" -e '$["txt"]'|grep -o useSSL)
        port=$(jsonfilter -s "$entry" -e '$["port"]')
	PORT=${port:-6543}

        if device_discover_server; then
            set_controller "$register"
            return 0
        fi

    done
}

_avahi_discovery() {
    local entries

    entries=$(avahi-browse -rcp _openwifi._tcp|grep =|grep IPv4)

    for entry in $entries ; do

        SERVER=$(echo "$entry" | awk -F";" '{print$8}')
        PORT=$(echo "$entry" | awk -F";" '{print $9}')
        txt=$(echo "$entry" | awk -F";" '{print $10}')
        WEB_ROOT=$(echo "$txt" | sed 's/path=\([^;]*\).*/\1/' | sed s/\"//g)
        SSL=$(echo "$txt"|grep -o useSSL)

        if device_discover_server ; then
            set_controller
            return 0
        fi

    done
}

# search for a openwifi controller and set it if found
device_discover() {
  local register=$1

  # check dns entry
  if device_discover_server "openwifi" "80" ; then
    set_controller "openwifi" "80" "" "$register"
    return 0
  fi

  # check if umdns is available
  if ubus list umdns ; then
      _umdns_discovery
      return $?
  else # use avahi as fallback
      _avahi_discovery
      return $?
  fi

  return 9
}

device_generate_uuid() {
  #ID Based on CPU and eth0
  local CPU_MD5=$(egrep "vendor|family|model|flags" /proc/cpuinfo | md5sum | sed "s/\s*-\s*//g")
  local ETH0_MAC_WITHOUT_COLONS=$(sed "s/://g" /sys/class/net/eth0/address)
  UUID=${CPU_MD5:0:8}-${CPU_MD5:8:4}-${CPU_MD5:12:4}-${CPU_MD5:16:4}-$ETH0_MAC_WITHOUT_COLONS

  uci set openwifi.@device[0].uuid="$UUID"
  uci commit openwifi
  return 0
}

# try to set the controller and register to it
set_controller() {
  local register=$1

  if [ "$register" != "doNotRegister" ]  ; then
    if ! device_register ; then
      return 10
    fi
  fi

  uci delete openwifi.@server[]
  uci add openwifi server
  uci set openwifi.@server[0].address="$SERVER"
  uci set openwifi.@server[0].port="$PORT"
  uci set openwifi.@server[0].path="$WEB_ROOT"
  uci set openwifi.@server[0].useSSL="$SSL"
  uci commit openwifi
  return 0
}

openwifi() {
  # check if a uuid was generated
  if [ -z "$UUID" ] ; then
    if ! device_generate_uuid ; then
      _log error "Could not generate a uuid"
      return 2
    fi
    uuid=$(uci get openwifi.@device[0].uuid)
  fi

  if [ -n "$SERVER" ] ; then
    if device_discover_server ; then
        set_controller "$register"
        return 0
    fi
  fi

  if ! device_discover ; then
    _log error "Could not discover a server"
    return 3
  fi
}

