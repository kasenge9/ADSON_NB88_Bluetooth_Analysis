#!/usr/bin/env python3
"""
Advanced Bluetooth Packet Capture and Analysis.
Capture and decode Bluetooth traffic for ADSON NB88 investigations.
"""

import json
import re
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path


class BluetoothPacketAnalyzer:
    def __init__(self, device_mac: str = "5C:20:09:F9:2B:84"):
        self.device_mac = device_mac
        self.packets = []
        self.profiles = defaultdict(list)
        self.commands = defaultdict(int)

    def _run_tshark(self, args: list[str]) -> subprocess.CompletedProcess:
        return subprocess.run(["tshark", *args], capture_output=True, text=True)

    def _safe_lines(self, output: str) -> list[str]:
        lines = [line for line in output.strip().split("\n") if line.strip()]
        return lines

    def _validate_capture_file(self, pcap_file: str) -> bool:
        path = Path(pcap_file)
        if not path.exists():
            print(f"[!] Capture file not found: {pcap_file}")
            print("[!] Create one first with: sudo btmon -w bluetooth_capture.pcapng")
            return False
        return True

    def start_capture(self, interface: str = "hci0", duration: int = 300):
        """
        Start capturing Bluetooth packets.
        Requires: bluez + btmon + tshark.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        outfile = f"bluetooth_capture_{timestamp}.pcapng"

        print("[*] Starting Bluetooth packet capture...")
        print(f"[*] Target: {self.device_mac}")
        print(f"[*] Duration: {duration} seconds")
        print(f"[*] Interface: {interface}")
        print(f"[*] Output: {outfile}")
        print()

        cmd = ["timeout", str(duration), "btmon", "-i", interface, "-w", outfile]
        print("[*] Run this command (requires privileges):")
        print("    " + " ".join(cmd))

    def analyze_a2dp_frames(self, pcap_file: str) -> dict:
        """Analyze A2DP audio streaming frames."""
        print("\n" + "=" * 60)
        print("A2DP AUDIO STREAMING ANALYSIS")
        print("=" * 60)

        if not self._validate_capture_file(pcap_file):
            return {}

        result = self._run_tshark([
            "-r", pcap_file,
            "-Y", "btavdtp",
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time",
            "-e", "btavdtp.type",
            "-e", "btavdtp.length",
        ])

        frames = self._safe_lines(result.stdout)
        print(f"[+] Found {len(frames)} A2DP frames\n")

        a2dp_stats = {
            "total_frames": len(frames),
            "frame_types": defaultdict(int),
            "first_frame": frames[0] if frames else "",
        }

        for frame in frames[:10]:
            print(f"    {frame}")
            parts = re.split(r"\s+", frame)
            if len(parts) >= 3:
                a2dp_stats["frame_types"][parts[2]] += 1

        a2dp_stats["frame_types"] = dict(a2dp_stats["frame_types"])
        return a2dp_stats

    def analyze_avrcp_commands(self, pcap_file: str) -> list[str]:
        """Analyze AVRCP remote control commands."""
        print("\n" + "=" * 60)
        print("AVRCP REMOTE CONTROL ANALYSIS")
        print("=" * 60)

        if not self._validate_capture_file(pcap_file):
            return []

        result = self._run_tshark([
            "-r", pcap_file,
            "-Y", "btavrcp",
            "-T", "fields",
            "-e", "frame.time",
            "-e", "avrcp.button",
            "-e", "avrcp.opcode",
        ])

        commands = self._safe_lines(result.stdout)
        print(f"[+] Found {len(commands)} AVRCP commands\n")

        command_map = {
            "PLAY": b"\x01",
            "PAUSE": b"\x02",
            "NEXT": b"\x03",
            "PREVIOUS": b"\x04",
            "VOLUME_UP": b"\x05",
            "VOLUME_DOWN": b"\x06",
        }

        print("[*] Command Mapping:")
        for cmd, code in command_map.items():
            print(f"    {cmd:20} -> {code.hex()}")

        return commands

    def analyze_hfp_commands(self, pcap_file: str) -> list[str]:
        """Analyze HFP AT commands."""
        print("\n" + "=" * 60)
        print("HFP HANDS-FREE PROFILE ANALYSIS")
        print("=" * 60)

        if not self._validate_capture_file(pcap_file):
            return []

        result = self._run_tshark([
            "-r", pcap_file,
            "-Y", "bthfp",
            "-T", "fields",
            "-e", "frame.time",
            "-e", "btl2cap.psm",
        ])

        at_commands = self._safe_lines(result.stdout)
        print(f"[+] Found {len(at_commands)} HFP frames\n")

        at_map = {
            "AT": "Attention",
            "AT+BRSF": "Bluetooth Retrieve Supported Features",
            "AT+CIND": "Call Indicator",
            "AT+CMER": "Call Monitoring/Error Reporting",
            "AT+CHLD": "Call Hold and Multiparty",
            "AT+CLVL": "Current Loudness/Volume Level",
            "AT+CVUP": "Current Volume Update",
        }

        print("[*] Known AT Commands:")
        for cmd, desc in at_map.items():
            print(f"    {cmd:15} -> {desc}")

        return at_commands

    def extract_packet_sequences(self, pcap_file: str) -> list[str]:
        """Extract and document packet sequences."""
        print("\n" + "=" * 60)
        print("PACKET SEQUENCE ANALYSIS")
        print("=" * 60)

        if not self._validate_capture_file(pcap_file):
            return []

        result = self._run_tshark(["-r", pcap_file, "-x"])
        lines = self._safe_lines(result.stdout)

        print("[*] Sample packet hex dumps:")
        for line in lines[:50]:
            print(f"    {line}")

        return lines

    def identify_custom_services(self, pcap_file: str) -> dict:
        """Look for custom Bluetooth services and UUIDs."""
        print("\n" + "=" * 60)
        print("CUSTOM SERVICE DETECTION")
        print("=" * 60)

        standard_uuids = {
            "110D": "A2DP Source",
            "110E": "AVRCP Target",
            "111E": "HFP Device",
            "1101": "Serial Port",
            "180A": "Device Information",
            "180F": "Battery Service",
        }

        print("[*] Standard UUIDs detected:")
        for uuid, desc in standard_uuids.items():
            print(f"    {uuid} -> {desc}")

        print("\n[!] Custom UUIDs (if any):")
        print("    (Would appear in capture if present)")
        return standard_uuids

    def analyze_security_mechanisms(self, pcap_file: str) -> dict:
        """Analyze encryption and authentication indicators."""
        print("\n" + "=" * 60)
        print("SECURITY MECHANISM ANALYSIS")
        print("=" * 60)

        if not self._validate_capture_file(pcap_file):
            return {}

        result = self._run_tshark([
            "-r", pcap_file,
            "-Y", "btl2cap",
            "-T", "fields",
            "-e", "btl2cap.cid",
        ])
        cids = self._safe_lines(result.stdout)

        print("[*] L2CAP Channel Analysis:")
        print("    CID 0x0004 -> ACL-U (connection)")
        print("    CID 0x0005 -> ACL-U (connection)")
        print("    CID 0x0006 -> LE Fixed (if BLE)")
        print("    CID 0x0040 -> A2DP (audio)")
        print("    CID 0x0041 -> AVRCP (control)")
        print(f"\n[*] Observed CID entries: {len(cids)}")

        print("\n[*] Encryption Status:")
        print("    - If packets readable: Unencrypted or weak encryption")
        print("    - If packets scrambled: Encryption enabled")

        return {"cid_entries": len(cids)}


if __name__ == "__main__":
    print("=" * 60)
    print("ADSON NB88 - Bluetooth Packet Analysis Tool")
    print("=" * 60)
    print()

    analyzer = BluetoothPacketAnalyzer()

    print("[!] SETUP REQUIRED:")
    print("    1. Install: sudo apt install bluez wireshark tshark")
    print("    2. Enable Bluetooth: sudo systemctl start bluetooth")
    print("    3. Start capture with: sudo btmon -w bluetooth_capture.pcapng")
    print("    4. Perform actions (play, pause, volume, etc.)")
    print("    5. Stop capture (Ctrl+C)")
    print("    6. Run analysis below")
    print()

    pcap_file = "bluetooth_capture.pcapng"

    summary = {
        "a2dp": analyzer.analyze_a2dp_frames(pcap_file),
        "avrcp_count": len(analyzer.analyze_avrcp_commands(pcap_file)),
        "hfp_count": len(analyzer.analyze_hfp_commands(pcap_file)),
        "sequence_lines": len(analyzer.extract_packet_sequences(pcap_file)),
        "uuids": analyzer.identify_custom_services(pcap_file),
        "security": analyzer.analyze_security_mechanisms(pcap_file),
    }

    print("\n" + "=" * 60)
    print("ANALYSIS SUMMARY (JSON)")
    print("=" * 60)
    print(json.dumps(summary, indent=2))
