#!/bin/sh
# Copyright 2016 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

umask 022
mkdir -p -m 0711 $LOCKBOX_CACHE_DIR
# /sbin/mount-encrypted emits the TPM NVRAM contents, if they exist, to a
# file on tmpfs which is used to authenticate the lockbox during cache
# creation.
if [ -O $LOCKBOX_NVRAM_FILE ]; then
  lockbox-cache --cache=$INSTALL_ATTRS_CACHE \
                --nvram=$LOCKBOX_NVRAM_FILE \
                --lockbox=$INSTALL_ATTRS_FILE
  # There are no other consumers; remove the nvram data
  rm $LOCKBOX_NVRAM_FILE
# IF WHALE
# Whale doesn't have TPM yet. Restore the removed upstream codes. https://source.chromium.org/chromiumos/_/chromium/chromiumos/platform2/+/9a2de0d377fdae131802e2c260721d2203d78009
# For VMs and legacy firmware devices, pretend like lockbox is supported.
elif crossystem "mainfw_type?nonchrome"; then
  cp $INSTALL_ATTRS_FILE $INSTALL_ATTRS_CACHE
# ENDIF
fi
