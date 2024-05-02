#!/bin/bash
set -ex

TARGET=${TARGET:-'x86/64'}
VERSION=${VERSION:-'22.03.3'}
REPOSITORY=${REPOSITORY:-'https://mirrors.tuna.tsinghua.edu.cn/openwrt'}
GCC_VERSION=${GCC_VERSION:-'11.2.0_musl'}
WORK_DIR=${WORK_DIR:-'/tmp/openwrt'}
SRC_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT_DIR=$( cd -- "$( dirname -- "${SRC_DIR}" )" &> /dev/null && pwd )
PACKAGES=$(tr '\n' ' ' < ${SRC_DIR}/packages/${VERSION}.txt)
if [[ $VERSION == "snapshots" ]]; then
  TAR_EXT='tar.zst'
  SDK=openwrt-sdk-${TARGET/\//-}_gcc-$GCC_VERSION.Linux-${TARGET/\//_}
  SDK_URL=$REPOSITORY/$VERSION/targets/$TARGET/$SDK.$TAR_EXT
  IMG_BUILDER=openwrt-imagebuilder-${TARGET/\//-}.Linux-${TARGET/\//_}
  IMG_BUILDER_URL=$REPOSITORY/$VERSION/targets/$TARGET/$IMG_BUILDER.$TAR_EXT
else
  TAR_EXT='tar.xz'
  SDK=openwrt-sdk-$VERSION-${TARGET/\//-}_gcc-$GCC_VERSION.Linux-${TARGET/\//_}
  SDK_URL=$REPOSITORY/releases/$VERSION/targets/$TARGET/$SDK.$TAR_EXT
  IMG_BUILDER=openwrt-imagebuilder-$VERSION-${TARGET/\//-}.Linux-${TARGET/\//_}
  IMG_BUILDER_URL=$REPOSITORY/releases/$VERSION/targets/$TARGET/$IMG_BUILDER.$TAR_EXT
fi

# Prepare working directory.
if [[ -d $WORK_DIR ]]; then
  rm -rf $WORK_DIR/*
else
  mkdir -p $WORK_DIR
fi
pushd $WORK_DIR

# OpenWRT cross-compilation SDK.
curl -sSLO $SDK_URL
tar -xf $SDK.$TAR_EXT
STAGING_DIR=$(realpath -- $SDK/staging_dir)
SDK_BIN_DIR=$(realpath -- $SDK/staging_dir/toolchain-${TARGET/\//_}_gcc-$GCC_VERSION/bin)
SDK_CC=${SDK_BIN_DIR}/${TARGET/\//_}-openwrt-linux-gcc
SDK_LD=${SDK_BIN_DIR}/${TARGET/\//_}-openwrt-linux-ld

# Prepare custom files.
$ROOT_DIR/common/secret_decoder.py -r $SRC_DIR/files ./files -e '.*skip$' '__pycache__'
mkdir -p files/usr/bin files/root
CUSTOM_FILES_DIR=$(realpath -- ./files)

# Sing-Box.
SING_BOX_VERSION=${SING_BOX_VERSION:-$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/SagerNet/sing-box/releases/latest | grep -Po 'v\K\d+\.\d+\.\d+')}
curl -sSL https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box-${SING_BOX_VERSION}-linux-amd64v3.tar.gz -o sing-box.tar.gz
tar -xf sing-box.tar.gz
chmod +x sing-box-${SING_BOX_VERSION}-linux-amd64v3/sing-box
mv sing-box-${SING_BOX_VERSION}-linux-amd64v3/sing-box $CUSTOM_FILES_DIR/usr/bin/

# Sing-Box web dashbord.
mkdir -p $CUSTOM_FILES_DIR/root/.config/sing-box
curl -sSLO https://github.com/MetaCubeX/yacd/archive/gh-pages.zip
unzip gh-pages.zip
mv Yacd-meta-gh-pages $CUSTOM_FILES_DIR/root/.config/sing-box/ui

# Sing-Box config.
$ROOT_DIR/conf-gen/generate.py -s $ROOT_DIR/conf-gen/source.yaml -o generated-conf/
cp generated-conf/sing-box-daemon.json $CUSTOM_FILES_DIR/root/.config/sing-box/config.json

# VLMCSD.
git clone https://github.com/Wind4/vlmcsd.git
pushd vlmcsd
STAGING_DIR=$STAGING_DIR PATH=$SDK_BIN_DIR:$PATH make CC=${SDK_CC} LD=${SDK_LD}
chmod +x bin/vlmcs bin/vlmcsd
popd
cp vlmcsd/bin/vlmcs vlmcsd/bin/vlmcsd $CUSTOM_FILES_DIR/usr/bin/

# DDNS.
rsync -aP --exclude='__pycache__' $ROOT_DIR/common $CUSTOM_FILES_DIR/root/
rsync -aP --exclude='__pycache__' $ROOT_DIR/util-cookbook/tencent-cloud $CUSTOM_FILES_DIR/root/util-cookbook/

# Image builder.
curl -sSLO $IMG_BUILDER_URL
tar -xf $IMG_BUILDER.$TAR_EXT
pushd $IMG_BUILDER
sed -i "s!https://downloads.openwrt.org!$REPOSITORY!" repositories.conf
make image ROOTFS_PARTSIZE=256 FILES=$CUSTOM_FILES_DIR PACKAGES="$PACKAGES"

popd  # Image builder.
popd  # Working directory.
