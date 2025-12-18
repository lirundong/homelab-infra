#!/bin/bash
set -ex

TARGET_ARCH=${TARGET_ARCH:-'x86/64'}
TOOLCHAIN_ARCH=${TOOLCHAIN_ARCH:-'x86/64'}
HOST_ARCH=${HOST_ARCH:-'x86/64'}
VERSION=${VERSION:-'22.03.3'}
REPOSITORY=${REPOSITORY:-'https://mirrors.tuna.tsinghua.edu.cn/openwrt'}
GCC_VERSION=${GCC_VERSION:-'11.2.0_musl'}
WORK_DIR=${WORK_DIR:-'/tmp/openwrt'}
TAR_EXT=${TAR_EXT:-'tar.zst'}
PROFILE=${PROFILE:-''}
SRC_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT_DIR=$( cd -- "$( dirname -- "${SRC_DIR}" )" &> /dev/null && pwd )
PACKAGES=$(tr '\n' ' ' < ${SRC_DIR}/packages/${VERSION}.txt)
if [[ $VERSION == 'snapshots' ]]; then
  SDK=openwrt-sdk-${TARGET_ARCH/\//-}_gcc-$GCC_VERSION.Linux-${HOST_ARCH/\//_}
  SDK_URL=$REPOSITORY/$VERSION/targets/$TARGET_ARCH/$SDK.$TAR_EXT
  IMG_BUILDER=openwrt-imagebuilder-${TARGET_ARCH/\//-}.Linux-${HOST_ARCH/\//_}
  IMG_BUILDER_URL=$REPOSITORY/$VERSION/targets/$TARGET_ARCH/$IMG_BUILDER.$TAR_EXT
  REPO_FILE=repositories
else
  SDK=openwrt-sdk-$VERSION-${TARGET_ARCH/\//-}_gcc-$GCC_VERSION.Linux-${HOST_ARCH/\//_}
  SDK_URL=$REPOSITORY/releases/$VERSION/targets/$TARGET_ARCH/$SDK.$TAR_EXT
  IMG_BUILDER=openwrt-imagebuilder-$VERSION-${TARGET_ARCH/\//-}.Linux-${HOST_ARCH/\//_}
  IMG_BUILDER_URL=$REPOSITORY/releases/$VERSION/targets/$TARGET_ARCH/$IMG_BUILDER.$TAR_EXT
  REPO_FILE=repositories.conf
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
if [[ ${TOOLCHAIN_ARCH} == 'aarch64' ]]; then
  SDK_BIN_DIR=$(realpath -- $SDK/staging_dir/toolchain-${TOOLCHAIN_ARCH}_generic_gcc-$GCC_VERSION/bin)
else
  SDK_BIN_DIR=$(realpath -- $SDK/staging_dir/toolchain-${TOOLCHAIN_ARCH/\//_}_gcc-$GCC_VERSION/bin)
fi
SDK_CC=${SDK_BIN_DIR}/${TOOLCHAIN_ARCH/\//_}-openwrt-linux-gcc
SDK_LD=${SDK_BIN_DIR}/${TOOLCHAIN_ARCH/\//_}-openwrt-linux-ld

# Prepare custom files.
$ROOT_DIR/common/secret_decoder.py -r $SRC_DIR/files ./files -e '.*skip$' '__pycache__'
mkdir -p files/usr/bin files/root
CUSTOM_FILES_DIR=$(realpath -- ./files)

# Build sing-box from source.
SING_BOX_VERSION=${SING_BOX_VERSION:-$(curl -Ls -o /dev/null -w %{url_effective} https://github.com/SagerNet/sing-box/releases/latest | grep -Po 'v\K\d+\.\d+\.\d+')}
SING_BOX_ARCH=${SING_BOX_ARCH:-'amd64'}
SING_BOX_CONFIG=${SING_BOX_CONFIG:-'artifacts-conf/sing-box-daemon/config.json'}
if [[ ! -f ${SING_BOX_CONFIG} ]]; then
  echo "sing-box configuration file ${SING_BOX_CONFIG} didn't exist"
  exit -1
fi
git clone --depth=1 --branch=v${SING_BOX_VERSION} https://github.com/SagerNet/sing-box.git
pushd sing-box
STAGING_DIR=$STAGING_DIR PATH=${SDK_BIN_DIR}:${PATH} CC=${SDK_CC} LD=${SDK_LD} GOOS=linux GOARCH=${SING_BOX_ARCH} GOAMD64=v3 CGO_ENABLED=1 make VERSION=${SING_BOX_VERSION} build
SING_BOX_OPENWRT_EXE=$(realpath ./sing-box)
popd
mkdir -p $CUSTOM_FILES_DIR/root/.config/sing-box
cp ${SING_BOX_OPENWRT_EXE} $CUSTOM_FILES_DIR/usr/bin/
cp ${SING_BOX_CONFIG} $CUSTOM_FILES_DIR/root/.config/sing-box/config.json

# Sing-Box web dashbord.
mkdir -p $CUSTOM_FILES_DIR/root/.config/sing-box
curl -sSLO https://github.com/MetaCubeX/yacd/archive/gh-pages.zip
unzip gh-pages.zip
mv Yacd-meta-gh-pages $CUSTOM_FILES_DIR/root/.config/sing-box/ui

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
image_builder_args=(ROOTFS_PARTSIZE=256 FILES=$CUSTOM_FILES_DIR PACKAGES="$PACKAGES")
if [[ -n ${PROFILE} ]]; then
  image_builder_args+=(PROFILE=$PROFILE)
fi
curl -sSLO $IMG_BUILDER_URL
tar -xf $IMG_BUILDER.$TAR_EXT
pushd $IMG_BUILDER
sed -i "s!https://downloads.openwrt.org!$REPOSITORY!" ${REPO_FILE}
make image "${image_builder_args[@]}"

popd  # Image builder.
popd  # Working directory.
