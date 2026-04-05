# Physical UART Access Guide

## Equipment Required
1. USB-to-UART Adapter (CH340G or FT232RL)
   - Cost: $3-10
   - 3.3V compatible (important!)

2. Soldering Iron
   - Temperature: 350°C
   - Fine tip recommended

3. Flux & Solder
   - Lead-free recommended
   - 0.5mm solder diameter

4. Magnifying Glass/Microscope
   - For identifying test points

5. Multimeter
   - For voltage verification

## Safety Precautions
- Disconnect battery before soldering
- Don't apply power while soldering
- Use flux to prevent cold joints
- Test connections with multimeter first

## Expected Bootloader Commands
```
AT+VERSION      → Firmware version
AT+FLASH_READ   → Read firmware
AT+FLASH_WRITE  → Write firmware
AT+RESET        → Reset device
```

## Next Steps
Once UART access achieved:
1. Identify bootloader type
2. Dump firmware for analysis
3. Check for signature verification
4. Document access method
