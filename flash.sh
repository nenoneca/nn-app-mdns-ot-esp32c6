#!/usr/bin/env bash
# Flash script for nn-app-mdns-ot-esp32c6 — executed BY THE HUB when the
# operator uses Factory → Flash a device.  The hub provides:
#   NN_FLASH_PORT     serial device to flash (e.g. /dev/ttyACM1)
#   NN_FLASH_IMAGE    path to this release's cached image.signed.bin
#   NN_FLASH_ESPTOOL  esptool invocation prefix (hub venv)
#
# App-only flash at 0x20000: preserves MCUboot, the partition table and
# NVS (keys + Thread dataset survive).  A factory-blank chip needs the
# bootloader set as well, which this release does not carry — flash that
# once from a bench, then this script covers every later (re)flash.
set -euo pipefail
: "${NN_FLASH_PORT:?}" "${NN_FLASH_IMAGE:?}"
${NN_FLASH_ESPTOOL:-python3 -m esptool} --chip esp32c6 -p "$NN_FLASH_PORT" -b 460800 \
  --before default-reset --after hard-reset \
  write-flash 0x20000 "$NN_FLASH_IMAGE"
