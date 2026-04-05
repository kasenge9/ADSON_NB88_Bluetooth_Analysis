# Hardware Analysis & Teardown Notes

## External Physical Inspection
- Plastic ear cups with soft padding
- Aluminum headband with adjustment
- USB-C port (charge-only, verified by ohmmeter)
- 3.5mm aux jack (passive, no data lines)
- Power/pairing button on side
- Volume rocker controls
- LED indicator (blue when connected)

## Suspected Internal Components
- Actions Semiconductor Bluetooth SoC
- Audio codec (likely integrated in SoC)
- Li-ion battery (~1000mAh)
- USB charging circuit
- Analog audio amplifier
- Speaker drivers (40mm estimated)

## UART Access Points (Estimated)
- TX/RX pins likely on SoC
- Possibly unpopulated test pads
- GND accessible from battery negative
- Voltage: 3.3V (Actions Semi standard)

## Not Recommended
- Opening device may void warranty
- Soldering can damage components
- Requires micro-soldering skills for safety
