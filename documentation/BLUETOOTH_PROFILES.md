# Bluetooth Profiles Analysis

## A2DP (Advanced Audio Distribution Profile)
- Purpose: Stereo audio streaming
- Service UUID: 110D
- Channel: 4 (discovered)
- Codec: SBC (Subband Codec)
- Bitrate: 128-192 kbps
- Status: OS-owned, read-only
- Exploitability: LOW

## AVRCP (Audio/Video Remote Control)
- Purpose: Media playback control
- Service UUID: 110E
- Commands: Play, Pause, Next, Previous, Volume Up/Down
- Status: Windows driver handles
- Exploitability: LOW

## HFP (Hands-Free Profile)
- Purpose: Hands-free calling
- Service UUID: 111E
- Channel: 2 (RFCOMM)
- AT Command Set: Limited
- Status: Virtual COM port (OS-owned)
- Exploitability: VERY LOW

## SPP (Serial Port Profile)
- Purpose: Generic serial communication
- Service UUID: 1101
- Status: NOT ADVERTISED
- Exploitability: N/A
