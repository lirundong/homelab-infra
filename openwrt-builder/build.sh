#!/bin/bash
set -ex

TARGET=${TARGET:-'x86/64'}
VERSION=${VERSION:-'21.02.2'}
REPOSITORY=${REPOSITORY:-'https://mirrors.tuna.tsinghua.edu.cn/openwrt'}
GCC_VERSION=${GCC_VERSION:-'8.4.0_musl'}
WORK_DIR=${WORK_DIR:-'/tmp/openwrt'}
SRC_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT_DIR=$( cd -- "$( dirname -- "${SRC_DIR}" )" &> /dev/null && pwd )
PACKAGES=$(tr '\n' ' ' < ${SRC_DIR}/packages-${VERSION}.txt)
if [[ $VERSION == "snapshots" ]]; then
  SDK=openwrt-sdk-${TARGET/\//-}_gcc-$GCC_VERSION.Linux-${TARGET/\//_}
  SDK_URL=$REPOSITORY/$VERSION/targets/$TARGET/$SDK.tar.xz
  IMG_BUILDER=openwrt-imagebuilder-${TARGET/\//-}.Linux-${TARGET/\//_}
  IMG_BUILDER_URL=$REPOSITORY/$VERSION/targets/$TARGET/$IMG_BUILDER.tar.xz
else
  SDK=openwrt-sdk-$VERSION-${TARGET/\//-}_gcc-$GCC_VERSION.Linux-${TARGET/\//_}
  SDK_URL=$REPOSITORY/releases/$VERSION/targets/$TARGET/$SDK.tar.xz
  IMG_BUILDER=openwrt-imagebuilder-$VERSION-${TARGET/\//-}.Linux-${TARGET/\//_}
  IMG_BUILDER_URL=$REPOSITORY/releases/$VERSION/targets/$TARGET/$IMG_BUILDER.tar.xz
fi

# Prepare working directory.
if [[ -d $WORK_DIR ]]; then
  rm -rf $WORK_DIR/*
else
  mkdir -p $WORK_DIR
fi
pushd $WORK_DIR

# Cross-compiled projects.
curl -sSLO $SDK_URL
tar -Jxf $SDK.tar.xz
STAGING_DIR=$(realpath -- $SDK/staging_dir)
SDK_BIN_DIR=$(realpath -- $SDK/staging_dir/toolchain-${TARGET/\//_}_gcc-$GCC_VERSION/bin)
# VLMCSD.
git clone https://github.com/Wind4/vlmcsd.git
pushd vlmcsd
STAGING_DIR=$STAGING_DIR PATH=$SDK_BIN_DIR:$PATH make CC=${TARGET/\//_}-openwrt-linux-gcc LD=${TARGET/\//_}-openwrt-linux-ld
chmod +x bin/vlmcs bin/vlmcsd
popd

# Prepare custom files.
$ROOT_DIR/common/secret_decoder.py -r $SRC_DIR/files ./files -e '.*skip$' '__pycache__'
mkdir -p files/usr/bin files/root
CUSTOM_FILES_DIR=$(realpath -- ./files)
# Clash.
CLASH_VERSION=$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/Dreamacro/clash/releases/latest | grep -Po 'v\K\d+\.\d+\.\d+')
curl -sSL https://github.com/Dreamacro/clash/releases/download/v$CLASH_VERSION/clash-linux-amd64-v3-v$CLASH_VERSION.gz -o clash.gz
gzip -d clash.gz
chmod +x clash
mv clash $CUSTOM_FILES_DIR/usr/bin/
# Clash config and dashboard.
mkdir -p $CUSTOM_FILES_DIR/root/.config/clash
git clone https://github.com/Dreamacro/clash-dashboard.git --branch=gh-pages --single-branch --depth=1 $CUSTOM_FILES_DIR/root/.config/clash/clash-dashboard
$ROOT_DIR/conf-gen/generate.py -s $ROOT_DIR/conf-gen/source.yaml -o clash-conf/
cp clash-conf/clash-daemon.yaml $CUSTOM_FILES_DIR/root/.config/clash/config.yaml
curl -sSL https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb -o $CUSTOM_FILES_DIR/root/.config/clash/Country.mmdb
# VLMCSD.
cp vlmcsd/bin/vlmcs vlmcsd/bin/vlmcsd $CUSTOM_FILES_DIR/usr/bin/
# DDNS.
rsync -aP --exclude='__pycache__' $ROOT_DIR/common $CUSTOM_FILES_DIR/root/
rsync -aP --exclude='__pycache__' $ROOT_DIR/util-cookbook/tencent-cloud $CUSTOM_FILES_DIR/root/util-cookbook/

# Image builder.
curl -sSLO $IMG_BUILDER_URL
tar -Jxf $IMG_BUILDER.tar.xz
pushd $IMG_BUILDER
sed -i "s!https://downloads.openwrt.org!$REPOSITORY!" repositories.conf
make image FILES=$CUSTOM_FILES_DIR PACKAGES="$PACKAGES"

popd  # Image builder.
popd  # Working directory.
