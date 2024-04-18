// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Macros and wrapper functions for dealing with ioctls.
//!
//! TODO: b/294107875 migrate to nix::ioctl macros

// Allow missing safety comments because this file provides just thin helper functions for
// `libc::ioctl`. Their safety follows `libc::ioctl`'s safety.
#![allow(clippy::missing_safety_doc)]

use std::os::raw::c_int;
use std::os::raw::c_uint;
use std::os::raw::c_ulong;
use std::os::raw::c_void;
use std::os::unix::io::AsRawFd;

/// Raw macro to declare the expression that calculates an ioctl number
#[macro_export]
macro_rules! ioctl_expr {
    ($dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        ((($dir as $crate::ioctl::IoctlNr) << $crate::ioctl::_IOC_DIRSHIFT)
            | (($ty as $crate::ioctl::IoctlNr) << $crate::ioctl::_IOC_TYPESHIFT)
            | (($nr as $crate::ioctl::IoctlNr) << $crate::ioctl::_IOC_NRSHIFT)
            | (($size as $crate::ioctl::IoctlNr) << $crate::ioctl::_IOC_SIZESHIFT))
    };
}
pub(crate) use ioctl_expr;

/// Raw macro to declare a function that returns an ioctl number.
#[macro_export]
macro_rules! ioctl_ioc_nr {
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr) => {
        #[allow(non_snake_case)]
        /// Generates ioctl request number.
        pub const fn $name() -> $crate::ioctl::IoctlNr {
            $crate::ioctl::ioctl_expr!($dir, $ty, $nr, $size)
        }
    };
    ($name:ident, $dir:expr, $ty:expr, $nr:expr, $size:expr, $($v:ident),+) => {
        #[allow(non_snake_case)]
        /// Generates ioctl request number.
        pub const fn $name($($v: ::std::os::raw::c_uint),+) -> $crate::ioctl::IoctlNr {
            $crate::ioctl::ioctl_expr!($dir, $ty, $nr, $size)
        }
    };
}
pub(crate) use ioctl_ioc_nr;

/// Declare an ioctl that transfers no data.
#[macro_export]
macro_rules! ioctl_io_nr {
    ($name:ident, $ty:expr, $nr:expr) => {
        $crate::ioctl::ioctl_ioc_nr!($name, $crate::ioctl::_IOC_NONE, $ty, $nr, 0);
    };
    ($name:ident, $ty:expr, $nr:expr, $($v:ident),+) => {
        $crate::ioctl::ioctl_ioc_nr!($name, $crate::ioctl::_IOC_NONE, $ty, $nr, 0, $($v),+);
    };
}
pub(crate) use ioctl_io_nr;

/// Declare an ioctl that reads data.
#[macro_export]
macro_rules! ioctl_ior_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        $crate::ioctl::ioctl_ioc_nr!(
            $name,
            $crate::ioctl::_IOC_READ,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl::ioctl_ioc_nr!(
            $name,
            $crate::ioctl::_IOC_READ,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32,
            $($v),+
        );
    };
}
pub(crate) use ioctl_ior_nr;

/// Declare an ioctl that writes data.
#[macro_export]
macro_rules! ioctl_iow_nr {
    ($name:ident, $ty:expr, $nr:expr, $size:ty) => {
        $crate::ioctl::ioctl_ioc_nr!(
            $name,
            $crate::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32
        );
    };
    ($name:ident, $ty:expr, $nr:expr, $size:ty, $($v:ident),+) => {
        $crate::ioctl::ioctl_ioc_nr!(
            $name,
            $crate::ioctl::_IOC_WRITE,
            $ty,
            $nr,
            ::std::mem::size_of::<$size>() as u32,
            $($v),+
        );
    };
}
pub(crate) use ioctl_iow_nr;

pub const _IOC_NRBITS: c_uint = 8;
pub const _IOC_TYPEBITS: c_uint = 8;
pub const _IOC_SIZEBITS: c_uint = 14;
pub const _IOC_DIRBITS: c_uint = 2;
pub const _IOC_NRMASK: c_uint = 255;
pub const _IOC_TYPEMASK: c_uint = 255;
pub const _IOC_SIZEMASK: c_uint = 16383;
pub const _IOC_DIRMASK: c_uint = 3;
pub const _IOC_NRSHIFT: c_uint = 0;
pub const _IOC_TYPESHIFT: c_uint = 8;
pub const _IOC_SIZESHIFT: c_uint = 16;
pub const _IOC_DIRSHIFT: c_uint = 30;
pub const _IOC_NONE: c_uint = 0;
pub const _IOC_WRITE: c_uint = 1;
pub const _IOC_READ: c_uint = 2;

#[cfg(any(target_os = "android", target_env = "musl"))]
pub type IoctlNr = c_int;
#[cfg(not(any(target_os = "android", target_env = "musl")))]
pub type IoctlNr = c_ulong;

/// Run an ioctl with no arguments.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl<F: AsRawFd>(descriptor: &F, nr: IoctlNr) -> c_int {
    libc::ioctl(descriptor.as_raw_fd(), nr, 0)
}

/// Run an ioctl with a single value argument.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_val(descriptor: &dyn AsRawFd, nr: IoctlNr, arg: c_ulong) -> c_int {
    libc::ioctl(descriptor.as_raw_fd(), nr, arg)
}

/// Run an ioctl with a raw pointer.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_ptr<T>(descriptor: &dyn AsRawFd, nr: IoctlNr, arg: *const T) -> c_int {
    libc::ioctl(descriptor.as_raw_fd(), nr, arg as *const c_void)
}

/// Run an ioctl with a mutable raw pointer.
/// # Safety
/// The caller is responsible for determining the safety of the particular ioctl.
pub unsafe fn ioctl_with_mut_ptr<T>(descriptor: &dyn AsRawFd, nr: IoctlNr, arg: *mut T) -> c_int {
    libc::ioctl(descriptor.as_raw_fd(), nr, arg as *mut c_void)
}

#[cfg(test)]
mod tests {
    const TUNTAP: ::std::os::raw::c_uint = 0x54;
    const VHOST: ::std::os::raw::c_uint = 0xaf;
    const EVDEV: ::std::os::raw::c_uint = 0x45;

    ioctl_io_nr!(VHOST_SET_OWNER, VHOST, 0x01);
    ioctl_ior_nr!(TUNGETFEATURES, TUNTAP, 0xcf, ::std::os::raw::c_uint);
    ioctl_iow_nr!(TUNSETQUEUE, TUNTAP, 0xd9, ::std::os::raw::c_int);

    ioctl_ior_nr!(EVIOCGBIT, EVDEV, 0x20 + evt, [u8; 128], evt);
    ioctl_io_nr!(FAKE_IOCTL_2_ARG, EVDEV, 0x01 + x + y, x, y);

    #[test]
    fn ioctl_macros() {
        assert_eq!(0x0000af01, VHOST_SET_OWNER());
        assert_eq!(0x800454cf, TUNGETFEATURES());
        assert_eq!(0x400454d9, TUNSETQUEUE());

        assert_eq!(0x80804522, EVIOCGBIT(2));
        assert_eq!(0x00004509, FAKE_IOCTL_2_ARG(3, 5));
    }
}
