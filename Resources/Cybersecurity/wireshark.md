## Scripts
Extract output of Keylogger USB Packets from Wireshark: [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)

## Filters 

Filter keylogger USB pcap / pcapng packets (NOTE: MAY BE OUTDATED)

```
usb.transfer_type == 0x01 and frame.len == 31 and !(usb.capdata == 00:00:00:00:00:00:00:00)
```