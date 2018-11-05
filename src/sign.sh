#!/bin/sh

host_os="$1"
inspector_binary="$2"
inspector_entitlements="$3"
signed_inspector_binary="$4"
ldid_binary="$5"
strip_binary="$6"
strip_enabled="$7"

if [ -z "$CODESIGN" ]; then
  echo "CODESIGN not set"
  exit 1
fi

case $host_os in
  macos)
    if [ -z "$MAC_CERTID" ]; then
      echo "MAC_CERTID not set, see https://github.com/frida/frida#macos-and-ios"
      exit 1
    fi
    ;;
  ios)
    if [ -z "$IOS_CERTID" ]; then
      echo "IOS_CERTID not set, see https://github.com/frida/frida#macos-and-ios"
      exit 1
    fi
    ;;
  *)
    echo "Unexpected host OS"
    exit 1
    ;;
esac

cp "$inspector_binary" "$signed_inspector_binary"

if [ "$strip_enabled" = "true" ]; then
  "$strip_binary" "$signed_inspector_binary"
fi

case $host_os in
  macos)
    "$CODESIGN" -f -s "$MAC_CERTID" -i "re.frida.ProcessInspector" "$signed_inspector_binary" || exit 1
    ;;
  ios)
    "$ldid_binary" "-S$inspector_entitlements" "$signed_inspector_binary" || exit 1
    ;;
esac
