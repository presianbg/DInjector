#!/usr/bin/env python3

import uuid


def convertToUUID(shellcode):
	if len(shellcode) % 16:
		#print('[*] Shellcode\'s length not multiplies of 16 bytes.')
		#print('[!] Adding nullbytes at the end of shellcode (this might break your shellcode).')
		#print(f'[+] Modified shellcode length: {len(shellcode) + (16 - (len(shellcode) % 16))}')
		
		null_nytes = b'\x00' * (16 - (len(shellcode) % 16))
		shellcode += null_nytes

	concatedUuids = b''
	for i in range(0, len(shellcode), 16):
		uuid_str = str(uuid.UUID(bytes_le=shellcode[i:i+16]))
		concatedUuids += uuid_str.encode() + b'|'

	return concatedUuids


if __name__ == '__main__':
	# buf = <SHELLCODE_BYTES>

	print(convertToUUID(buf)[:-1], end='')
