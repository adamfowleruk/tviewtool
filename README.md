# Hollong Viewtool command line utilities

This repository contains a command line tool for the Hollong Viewtool called tviewtool.

This enables you to monitor all traffic on channels 37, 38, 39 and thus all advertisements.

No need to use the ble_sniffer GUI app any longer!

## Compilation

First you must download the libraries for the viewtool:-

1. Download ble_sniffer for your operating system and install it
1. Grab the libble_sniffer_driver (all platforms) and libusb-1.0.0 (mac only) libraries and copy them to this folder
1. mkdir Debug
1. mkdir Debug/bin
1. mkdir Debug/bin/Release
1. cp libble* Debug/bin/Release
1. cp libusb* Debug

Now you can build the project:-

1. Download QT-Creator
1. Run QTCreator
1. Open the tviewtool.pro project file
1. Build the project

## Usage

Currently the only operating mode is raw mode. This will grab all output from tthe Viewtool and log it in a CSV style format for later analysis.

```sh
$> tviewtool
1590879095115435,Raw:Viewtool,39,0,10752,53035332861,37,0x8e89bed6,6208,24,4dbd773e887f02011a020a0c0bff4c001006131a5f82f936,e738a7
1590879095116059,Raw:Viewtool,39,0,10496,53035338855,36,0x8e89bed6,5952,23,9f4ab7fa676902011a020a0c0aff4c001005031873596c,9938a7
1590879095127889,Raw:Viewtool,39,0,10496,53035356290,36,0x8e89bed6,5952,23,37421802ac7402011a020a0c0aff4c0010050a189dd2af,ad28a7
1590879095164736,Raw:Viewtool,38,0,9728,53035378328,33,0x8e89bed6,5184,20,c3db49b0de5802011a0aff4c001005031c5d7264,cc30a6
1590879095165982,Raw:Viewtool,37,0,9728,53034220188,33,0x8e89bed6,5184,20,c3db49b0de5802011a0aff4c001005031c5d7264,cc38a5
1590879095201779,Raw:Viewtool,39,0,10496,53035378743,36,0x8e89bed6,5952,23,b09d493ee27b02011a020a0c0aff4c0010054c1c3cfb68,a728a7
1590879095202383,Raw:Viewtool,37,0,10496,53034257141,36,0x8e89bed6,5952,23,a9496adb2e5902011a020a0c0aff4c001005031c03d3a4,6030a5
1590879095203067,Raw:Viewtool,38,0,10752,53035389643,37,0x8e89bed6,6208,24,4dbd773e887f02011a020a0c0bff4c001006131a5f82f936,e738a6
```

An example CSV header file is below:-
```csv
CaptureTimeMicroseconds,Format,Channel,Preamble1m,Preamble2m,Timestamp,TenthByte,AccessAddressHex,PDUHeader,PayloadDataLength,PayloadData,CRC
```

Note: The PayloadData on Bluetooth from the Viewtool is encoded as Little Endian. Thus for individual fields in the data (NOT the whole data) you will have to reverse the position of each byte. The byte itself is encoded correctly.

You can also pipe the data to a log file instead for later analysis:-

```sh
$> tviewtool > sample.txt
```

## Copyright & Licensing

Copyright Adam Fowler 2020. Licensed under the MIT license.
