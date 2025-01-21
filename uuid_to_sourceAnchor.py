#!/usr/bin/env python3
import base64
import uuid
import struct
import sys

def uuid_to_windows_le(uuid_string):
    # Convert the string to a UUID object
    uuid_obj = uuid.UUID(uuid_string)

    # Unpack UUID fields
    time_low, time_mid, time_hi_and_version = struct.unpack(">IHH", uuid_obj.bytes[:8])
    clock_seq_and_node = uuid_obj.bytes[8:]

    # Repack with Little-Endian for first three fields
    windows_le = struct.pack("<IHH", time_low, time_mid, time_hi_and_version) + clock_seq_and_node

    return windows_le

# Example UUID
uuid_string = sys.argv[1]

# Convert to Windows LE binary
windows_le_binary = uuid_to_windows_le(uuid_string)
source_anchor = base64.b64encode(windows_le_binary)

print(f"[*] Windows LE Binary: {windows_le_binary}")
print(f"[*] Source Anchor: {source_anchor}")
