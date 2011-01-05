# See http://www.ietf.org/rfc/rfc2440.txt for ASCII Armor specs.

import base64
import struct

CRC24_INIT = 0xB704CE
CRC24_POLY = 0x1864CFB

def crc24( data ):
	crc = CRC24_INIT
	for byte in data:
		crc ^= (ord(byte) << 16)
		for i in xrange(8):
			crc <<= 1
			if crc & 0x1000000:
				crc ^= CRC24_POLY
	return crc & 0xFFFFFF

def armor( data ):
	template = '-----BEGIN PGP MESSAGE-----\n%(headers)s\n\n%(body)s\n=%(crc)s\n-----END PGP MESSAGE-----'
	headers = ['Version: django-pgcrypto 1.0']
	body = base64.b64encode( data )
	crc = base64.b64encode( struct.pack('>L', crc24(data))[1:] )
	return template % {
		'headers': '\n'.join(headers),
		'body': body,
		'crc': crc
	}

class BadChecksumError (Exception):
	pass

def dearmor( text, verify=True ):
	lines = text.strip().split( '\n' )
	data_lines = []
	check_data = None
	started = False
	in_body = False
	for line in lines:
		if line.startswith('-----BEGIN'):
			started = True
		elif line.startswith('-----END'):
			break
		elif started:
			if in_body:
				if line.startswith('='):
					# Once we get the checksum data, we're done.
					check_data = line[1:5]
					break
				else:
					# This is part of the base64-encoded data.
					data_lines.append( line )
			else:
				if line.strip():
					# This is a header line, which we basically ignore for now.
					pass
				else:
					# The data starts after an empty line.
					in_body = True
	data = base64.b64decode( ''.join(data_lines) )
	if verify and check_data:
		crc = struct.unpack( '>L', '\0'+base64.b64decode(check_data) )[0]
		if crc != crc24(data):
			raise BadChecksumError()
	return data

def unpad( text ):
	"""
	Strips off any bytes with a value less than 8 from the end of the text string. This
	means you can't use any of those bytes in your data, but that is OK for most purposes.
	"""
	end = len(text)
	while ord(text[end-1]) < 8:
		end -= 1
	return text[:end]

def pad( text, block_size ):
	"""
	Given a text string and a block size, pads the text with bytes of the same value
	as the number of padding bytes. This is the recommended method, and the one used
	by pgcrypto. See http://www.di-mgt.com.au/cryptopad.html for more information.
	"""
	num = block_size - (len(text) % block_size)
	return text + (chr(num) * num)

if __name__ == '__main__':
	from Crypto.Cipher import Blowfish
	# This is the expected encrypted value, according to the following pgcrypto call:
	#   select encrypt('sensitive information', 'pass', 'bf');
	d = "x\364r\225\356WH\347\240\205\211a\223I{~\233\034\347\217/f\035\005"
	# Test encryption and padding.
	c = Blowfish.new( 'pass', Blowfish.MODE_CBC )
	assert c.encrypt( pad('sensitive information', c.block_size) ) == d
	# Test decryption and unpadding.
	c = Blowfish.new( 'pass', Blowfish.MODE_CBC )
	assert unpad( c.decrypt(d) ) == 'sensitive information'
	# Test armor and dearmor.
	a = armor( d )
	assert dearmor( a ) == d
