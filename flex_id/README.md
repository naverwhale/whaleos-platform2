# Chrome OS Flex ID
This is a utility and library for generating a device-specific identifier
known as a Flex ID. This was previously named Client ID, and is also
a separate identifier from the client id used in UMA and crash reporting.

Flex ID can be used to account for the lack of VPD information by
amd64 generic based platforms (such as the Reven board).

This utility will check a number of locations to attempt to find a useful
source to define a non-random device identifier.

The Flex ID is stored at `/var/lib/flex_id/flex_id`.

## Preserved Flex ID
The Flex ID is preserved through power wash and saved to
`mnt/stateful_partition/unencrypted/preserve/flex/flex_id`.

## CloudReady Legacy Client ID
This is a Client ID generated by CloudReady devices that is stored at
`mnt/stateful_partition/cloudready/client_id`. It consists of the device's mac
address and should be prepended with `CloudReady-`.

## DMI Serial Number
This is the serial number from DMI/SMBIOS information, read from
`/sys/devices/virtual/dmi/id/product_serial`. Serial number is not guaranteed
to be useful. There are certain criteria such as minimum length, and comparison
with known bad strings that must be met to be useful.

## MAC Address
This is the best case hardware MAC address that can be read from
`/sys/class/net/<device name>/address`. Priority is given to `eth0` and `wlan0`.

## Kernel UUID
If all of the above fails, a random UUID generated from
`/proc/sys/kernel/random/uuid` will be used.