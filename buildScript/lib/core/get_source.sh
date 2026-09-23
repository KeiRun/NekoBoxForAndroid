#!/bin/bash
set -e
source "buildScript/init/env.sh"
ENV_NB4A=1
source "buildScript/lib/core/get_source_env.sh"
BYEDPI_PATCH=$(realpath "patches/byedpi/0001-byedpi-jni-api.patch")
SING_BOX_PATCH=$(realpath "patches/core/sing-box.patch")
LIBNEKO_PATCH=$(realpath "patches/core/libneko.patch")
SING_VMESS_PATCH=$(realpath "patches/core/sing-vmess.patch")
MASTER_DNS_PATCH=$(realpath "patches/core/MasterDnsVPN.patch")
pushd ..
#### sing-box
if [ ! -d "sing-box" ]; then
  git clone --depth 1 --branch v1.14.0 https://github.com/SagerNet/sing-box.git sing-box
  pushd sing-box
  git apply "$SING_BOX_PATCH"
  popd
fi
#### sing-vmess
if [ ! -d "sing-vmess" ]; then
  git clone --depth 1 --branch dev https://github.com/starifly/sing-vmess.git sing-vmess
  pushd sing-vmess
  git apply "$SING_VMESS_PATCH"
  popd
fi
#### libneko
if [ ! -d "libneko" ]; then
  git clone --depth 1 --branch main https://github.com/starifly/libneko.git libneko
  pushd libneko
  git apply "$LIBNEKO_PATCH"
  popd
fi
#### MasterDnsVPN-plus
if [ ! -d "MasterDnsVPN-plus" ]; then
  git clone --depth 1 --branch v2026.06.13.234407-7de2476 https://github.com/masterking32/MasterDnsVPN.git MasterDnsVPN-plus
  pushd MasterDnsVPN-plus
  git apply "$MASTER_DNS_PATCH"
  popd
fi
#### amneziawg-go & utls
if [ ! -d "amneziawg-go" ]; then
  git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go.git amneziawg-go
fi
if [ ! -d "utls" ]; then
  git clone --depth 1 https://github.com/metacubex/utls.git utls
fi
#### byedpi
if [ ! -d "byedpi" ]; then
  git clone https://github.com/hufrea/byedpi.git byedpi
  pushd byedpi
  git checkout ba532298de7b28cfe854aea83d061369d13ca290
  git apply "$BYEDPI_PATCH" || true
  popd
fi
popd
