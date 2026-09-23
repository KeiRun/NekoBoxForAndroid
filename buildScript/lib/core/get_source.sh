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
  git clone --depth 50 https://github.com/SagerNet/sing-box.git sing-box
  pushd sing-box
  git checkout 0b8995879f29a9b98ee027bc17b75e101445b238
  git apply "$SING_BOX_PATCH"
  popd
fi
#### sing-vmess
if [ ! -d "sing-vmess" ]; then
  git clone --depth 50 https://github.com/starifly/sing-vmess.git sing-vmess
  pushd sing-vmess
  git checkout 887f058c04c5b86d88188acc32093d0d62f53b6c
  git apply "$SING_VMESS_PATCH"
  popd
fi
#### libneko
if [ ! -d "libneko" ]; then
  git clone --depth 50 https://github.com/starifly/libneko.git libneko
  pushd libneko
  git checkout 6a85c185d62435a5293ef70ac3b638ae3ee1efa7
  git apply "$LIBNEKO_PATCH"
  popd
fi
#### MasterDnsVPN-plus
if [ ! -d "MasterDnsVPN-plus" ]; then
  git clone https://github.com/masterking32/MasterDnsVPN.git MasterDnsVPN-plus
  pushd MasterDnsVPN-plus
  git checkout 7de2476f1c33e69eec35360c52810dab43c5c986
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
