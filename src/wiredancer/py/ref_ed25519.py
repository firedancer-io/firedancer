# RFC8032 reference implementation pages 20-23
#         + test vectors pages 24-27

# NOTE: it needs python3 (3.6) to run

import hashlib

def sha512(s):
	return hashlib.sha512(s).digest()

# Base field Z_p
p = 2**255 - 19

def modp_inv(x):
	return pow(x, p-2, p)

# Curve constant
d = -121665 * modp_inv(121666) % p

# Group order
q = 2**252 + 27742317777372353535851937790883648493

def sha512_modq(s):
	return int.from_bytes(sha512(s), "little") % q

## Then follows functions to perform point operations.
# Points are represented as tuples (X, Y, Z, T) of extended
# coordinates, with x = X/Z, y = Y/Z, x*y = T/Z
def point_add(P, Q):
	A, B = ((P[1]-P[0]) * (Q[1]-Q[0])) % p, ((P[1]+P[0]) * (Q[1]+Q[0])) % p;
	C, D = (2 * P[3] * Q[3] * d) % p, (2 * P[2] * Q[2]) % p;
	E, F, G, H = (B-A)%p, (D-C)%p, (D+C)%p, (B+A)%p;
	return ((E*F) % p, (G*H) % p, (F*G) % p, (E*H) % p);



# Computes Q = s * Q
def point_mul(s, P):
	Q = (0, 1, 1, 0) # Neutral element
	while s > 0:
		if s & 1:
			Q = point_add(Q, P)
		P = point_add(P, P)
		s >>= 1
	return (Q[0]%p, Q[1]%p, Q[2]%p, Q[3]%p)

def point_equal(P, Q):
	# x1 / z1 == x2 / z2 <==> x1 * z2 == x2 * z1
	if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
		return False
	if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
		return False
	return True

## Now follows functions for point compression.
# Square root of -1
modp_sqrt_m1 = pow(2, (p-1) // 4, p)
# Compute corresponding x-coordinate, with low bit corresponding to
# sign, or return None on failure
def recover_x(y, sign):
	if y >= p:
		return None
	x2 = (y*y-1) * modp_inv(d*y*y+1)
	if x2 == 0:
		if sign:
			return None
		else:
			return 0
	
	# Compute square root of x2
	x = pow(x2, (p+3) // 8, p)
	if (x*x - x2) % p != 0:
		x = x * modp_sqrt_m1 % p
	if (x*x - x2) % p != 0:
		return None
	if (x & 1) != sign:
		x = p - x
	return x

# Base point
g_y = 4 * modp_inv(5) % p
g_x = recover_x(g_y, 0)
G = (g_x, g_y, 1, g_x * g_y % p)

def point_compress(P):
	zinv = modp_inv(P[2])
	x = P[0] * zinv % p
	y = P[1] * zinv % p
	return int.to_bytes(y | ((x & 1) << 255), 32, "little")

def point_decompress(s):
	if len(s) != 32:
		raise Exception("Invalid input length for decompression")
	y = int.from_bytes(s, "little")
	sign = y >> 255
	y &= (1 << 255) - 1
	
	x = recover_x(y, sign)
	if x is None:
		return None
	else:
		return (x, y, 1, x*y % p)

## These are functions for manipulating the private key.
def secret_expand(secret):
	if len(secret) != 32:
		raise Exception("Bad size of private key")
	h = sha512(secret)
	a = int.from_bytes(h[:32], "little")
	a &= (1 << 254) - 8
	a |= (1 << 254)
	return (a, h[32:])

def secret_to_public(secret):
	(a, dummy) = secret_expand(secret)
	return point_compress(point_mul(a, G))

## The signature function works as below.
def sign(secret, msg):
	a, prefix = secret_expand(secret)
	A = point_compress(point_mul(a, G))
	r = sha512_modq(prefix + msg)
	R = point_mul(r, G)
	Rs = point_compress(R)
	h = sha512_modq(Rs + A + msg)
	s = (r + h * a) % q
	return Rs + int.to_bytes(s, 32, "little")

## And finally the verification function.
def verify2(public, msg, signature, h=None):
	if len(public) != 32:
		raise Exception("Bad public key length")
	if len(signature) != 64:
		Exception("Bad signature length")
	A = point_decompress(public)
	if not A:
		return False
	Rs = signature[:32]
	R = point_decompress(Rs)
	if not R:
		return False
	s = int.from_bytes(signature[32:], "little")
	if s >= q: return False
	if h == None:
		h = sha512_modq(Rs + public + msg)
	sB = point_mul(s, G)
	hA = point_mul(h, A)
	return point_equal(sB, point_add(R, hA))

## And finally the verification function.
def verify(public, msg, signature, h=None):
	if len(public) != 32:
		raise Exception("Bad public key length")
	if len(signature) != 64:
		Exception("Bad signature length")
	A = point_decompress(public)
	if not A:
		return False
	Rs = signature[:32]
	R = point_decompress(Rs)
	if not R:
		return False
	s = int.from_bytes(signature[32:], "little")
	if s >= q: return False
	if h == None:
		h = sha512_modq(Rs + public + msg)
	# sB = point_mul(s, G)
	# hA = point_mul(h, A)
	# return point_equal(sB, point_add(R, hA))

	P0 = point_mul(s, G)
	P1 = point_mul(h, A)
	P0P1 = point_add(P0, P1)

	An = ((p-A[0]), A[1], A[2], (p-A[3]))
	T = point_add(G, An)
	Z = (0, 1, 1, 0)
	for i in range(255, -1, -1):
		Z = point_add(Z, Z)
		b0 = (s >> i) & 1
		b1 = (h >> i) & 1

		Q = (0, 1, 1, 0)
		if b0 == 1 and b1 == 1:
			Q = T
		elif b0 == 1:
			Q = G
		elif b1 == 1:
			Q = An

		Z = point_add(Z, Q)

	# print (point_equal(P0P1, Z))

	return point_equal(Z, R)


# ###############################################################
# Test Vectors

def TEST_VERIF( n, keyP, msg, sigt ):
	print( " " )
	print( "TEST {}".format(n) )
	print( "Public Key  : 0x{}".format(keyP[  :16].hex()))
	print( "                {}".format(keyP[16:  ].hex()))
	print( "Message     : 0x{}".format(msg [  :16].hex()))
	for i in range(16,len(msg),16):
		print( "                {}".format(msg[i:i+16].hex()))
	print( "Signature   : 0x{}".format(sigt[  :16].hex()))
	print( "                {}".format(sigt[16:32].hex()))
	print( "                {}".format(sigt[32:48].hex()))
	print( "                {}".format(sigt[48:64].hex()))
	v = verify(keyP, msg, sigt)
	print( "Verif pass? : {}".format(v) )
	assert v, "!"


# https://stackoverflow.com/questions/5649407/hexadecimal-string-to-byte-array-in-python
if __name__ == '__main__':

	print ('{:x} {}'.format(G[0], G[0].bit_length()))
	print ('{:x} {}'.format(G[1], G[1].bit_length()))
	print ('{:x} {}'.format(G[2], G[2].bit_length()))
	print ('{:x} {}'.format(G[3], G[3].bit_length()))
	print ('{:x} {}'.format(d, d.bit_length()))
	print ('{:x} {}'.format((d+d)%p, d.bit_length()))

	# -----TEST 1
	# ALGORITHM:
	# Ed25519
	# SECRET KEY:
	keyS = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4")
	keyS+= bytes.fromhex("4449c5697b326919703bac031cae7f60")
	# PUBLIC KEY:
	keyP = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a")
	keyP+= bytes.fromhex("0ee172f3daa62325af021a68f707511a")
	# MESSAGE (length 0 bytes):
	msg = b''
	# SIGNATURE:
	sigt = bytes.fromhex("e5564300c360ac729086e2cc806e828a")
	sigt+= bytes.fromhex("84877f1eb8e5d974d873e06522490155")
	sigt+= bytes.fromhex("5fb8821590a33bacc61e39701cf9b46b")
	sigt+= bytes.fromhex("d25bf5f0595bbe24655141438e7a100b")
	TEST_VERIF( 1, keyP, msg, sigt )


	# -----TEST 2
	# ALGORITHM:
	# Ed25519
	# SECRET KEY:
	keyS = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f")
	keyS+= bytes.fromhex("5b8a319f35aba624da8cf6ed4fb8a6fb")
	# PUBLIC KEY:
	keyP = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc")
	keyP+= bytes.fromhex("9c982ccf2ec4968cc0cd55f12af4660c")
	# MESSAGE (length 1 byte):
	msg  = bytes.fromhex("72")
	# SIGNATURE:
	sigt = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540")
	sigt+= bytes.fromhex("a2b27b5416503f8fb3762223ebdb69da")
	sigt+= bytes.fromhex("085ac1e43e15996e458f3613d0f11d8c")
	sigt+= bytes.fromhex("387b2eaeb4302aeeb00d291612bb0c00")
	TEST_VERIF( 2, keyP, msg, sigt )


	# -----TEST 3
	# ALGORITHM:
	# Ed25519
	# SECRET KEY:
	keyS = bytes.fromhex("c5aa8df43f9f837bedb7442f31dcb7b1")
	keyS+= bytes.fromhex("66d38535076f094b85ce3a2e0b4458f7")
	# PUBLIC KEY:
	keyP = bytes.fromhex("fc51cd8e6218a1a38da47ed00230f058")
	keyP+= bytes.fromhex("0816ed13ba3303ac5deb911548908025")
	# MESSAGE (length 2 bytes):
	msg  = bytes.fromhex("af82")
	# SIGNATURE:
	sigt = bytes.fromhex("6291d657deec24024827e69c3abe01a3")
	sigt+= bytes.fromhex("0ce548a284743a445e3680d7db5ac3ac")
	sigt+= bytes.fromhex("18ff9b538d16f290ae67f760984dc659")
	sigt+= bytes.fromhex("4a7c15e9716ed28dc027beceea1ec40a")
	TEST_VERIF( 3, keyP, msg, sigt )


	# -----TEST 1024
	# ALGORITHM:
	# Ed25519
	# SECRET KEY:
	keyS = bytes.fromhex("f5e5767cf153319517630f226876b86c")
	keyS+= bytes.fromhex("8160cc583bc013744c6bf255f5cc0ee5")
	# PUBLIC KEY:
	keyP = bytes.fromhex("278117fc144c72340f67d0f2316e8386")
	keyP+= bytes.fromhex("ceffbf2b2428c9c51fef7c597f1d426e")
	# MESSAGE (length 1023 bytes):
	msg  = bytes.fromhex("08b8b2b733424243760fe426a4b54908")
	msg += bytes.fromhex("632110a66c2f6591eabd3345e3e4eb98")
	msg += bytes.fromhex("fa6e264bf09efe12ee50f8f54e9f77b1")
	msg += bytes.fromhex("e355f6c50544e23fb1433ddf73be84d8")
	msg += bytes.fromhex("79de7c0046dc4996d9e773f4bc9efe57")
	msg += bytes.fromhex("38829adb26c81b37c93a1b270b20329d")
	msg += bytes.fromhex("658675fc6ea534e0810a4432826bf58c")
	msg += bytes.fromhex("941efb65d57a338bbd2e26640f89ffbc")
	msg += bytes.fromhex("1a858efcb8550ee3a5e1998bd177e93a")
	msg += bytes.fromhex("7363c344fe6b199ee5d02e82d522c4fe")
	msg += bytes.fromhex("ba15452f80288a821a579116ec6dad2b")
	msg += bytes.fromhex("3b310da903401aa62100ab5d1a36553e")
	msg += bytes.fromhex("06203b33890cc9b832f79ef80560ccb9")
	msg += bytes.fromhex("a39ce767967ed628c6ad573cb116dbef")
	msg += bytes.fromhex("efd75499da96bd68a8a97b928a8bbc10")
	msg += bytes.fromhex("3b6621fcde2beca1231d206be6cd9ec7")
	msg += bytes.fromhex("aff6f6c94fcd7204ed3455c68c83f4a4")
	msg += bytes.fromhex("1da4af2b74ef5c53f1d8ac70bdcb7ed1")
	msg += bytes.fromhex("85ce81bd84359d44254d95629e9855a9")
	msg += bytes.fromhex("4a7c1958d1f8ada5d0532ed8a5aa3fb2")
	msg += bytes.fromhex("d17ba70eb6248e594e1a2297acbbb39d")
	msg += bytes.fromhex("502f1a8c6eb6f1ce22b3de1a1f40cc24")
	msg += bytes.fromhex("554119a831a9aad6079cad88425de6bd")
	msg += bytes.fromhex("e1a9187ebb6092cf67bf2b13fd65f270")
	msg += bytes.fromhex("88d78b7e883c8759d2c4f5c65adb7553")
	msg += bytes.fromhex("878ad575f9fad878e80a0c9ba63bcbcc")
	msg += bytes.fromhex("2732e69485bbc9c90bfbd62481d9089b")
	msg += bytes.fromhex("eccf80cfe2df16a2cf65bd92dd597b07")
	msg += bytes.fromhex("07e0917af48bbb75fed413d238f5555a")
	msg += bytes.fromhex("7a569d80c3414a8d0859dc65a46128ba")
	msg += bytes.fromhex("b27af87a71314f318c782b23ebfe808b")
	msg += bytes.fromhex("82b0ce26401d2e22f04d83d1255dc51a")
	msg += bytes.fromhex("ddd3b75a2b1ae0784504df543af8969b")
	msg += bytes.fromhex("e3ea7082ff7fc9888c144da2af58429e")
	msg += bytes.fromhex("c96031dbcad3dad9af0dcbaaaf268cb8")
	msg += bytes.fromhex("fcffead94f3c7ca495e056a9b47acdb7")
	msg += bytes.fromhex("51fb73e666c6c655ade8297297d07ad1")
	msg += bytes.fromhex("ba5e43f1bca32301651339e22904cc8c")
	msg += bytes.fromhex("42f58c30c04aafdb038dda0847dd988d")
	msg += bytes.fromhex("cda6f3bfd15c4b4c4525004aa06eeff8")
	msg += bytes.fromhex("ca61783aacec57fb3d1f92b0fe2fd1a8")
	msg += bytes.fromhex("5f6724517b65e614ad6808d6f6ee34df")
	msg += bytes.fromhex("f7310fdc82aebfd904b01e1dc54b2927")
	msg += bytes.fromhex("094b2db68d6f903b68401adebf5a7e08")
	msg += bytes.fromhex("d78ff4ef5d63653a65040cf9bfd4aca7")
	msg += bytes.fromhex("984a74d37145986780fc0b16ac451649")
	msg += bytes.fromhex("de6188a7dbdf191f64b5fc5e2ab47b57")
	msg += bytes.fromhex("f7f7276cd419c17a3ca8e1b939ae49e4")
	msg += bytes.fromhex("88acba6b965610b5480109c8b17b80e1")
	msg += bytes.fromhex("b7b750dfc7598d5d5011fd2dcc5600a3")
	msg += bytes.fromhex("2ef5b52a1ecc820e308aa342721aac09")
	msg += bytes.fromhex("43bf6686b64b2579376504ccc493d97e")
	msg += bytes.fromhex("6aed3fb0f9cd71a43dd497f01f17c0e2")
	msg += bytes.fromhex("cb3797aa2a2f256656168e6c496afc5f")
	msg += bytes.fromhex("b93246f6b1116398a346f1a641f3b041")
	msg += bytes.fromhex("e989f7914f90cc2c7fff357876e506b5")
	msg += bytes.fromhex("0d334ba77c225bc307ba537152f3f161")
	msg += bytes.fromhex("0e4eafe595f6d9d90d11faa933a15ef1")
	msg += bytes.fromhex("369546868a7f3a45a96768d40fd9d034")
	msg += bytes.fromhex("12c091c6315cf4fde7cb68606937380d")
	msg += bytes.fromhex("b2eaaa707b4c4185c32eddcdd306705e")
	msg += bytes.fromhex("4dc1ffc872eeee475a64dfac86aba41c")
	msg += bytes.fromhex("0618983f8741c5ef68d3a101e8a3b8ca")
	msg += bytes.fromhex("c60c905c15fc910840b94c00a0b9d0")
	# SIGNATURE:
	sigt = bytes.fromhex("0aab4c900501b3e24d7cdf4663326a3a")
	sigt+= bytes.fromhex("87df5e4843b2cbdb67cbf6e460fec350")
	sigt+= bytes.fromhex("aa5371b1508f9f4528ecea23c436d94b")
	sigt+= bytes.fromhex("5e8fcd4f681e30a6ac00a9704a188a03")
	TEST_VERIF( 4, keyP, msg, sigt )


	# -----TEST SHA(abc)
	# ALGORITHM:
	# Ed25519
	# SECRET KEY:
	keyS = bytes.fromhex("833fe62409237b9d62ec77587520911e")
	keyS+= bytes.fromhex("9a759cec1d19755b7da901b96dca3d42")
	# PUBLIC KEY:
	keyP = bytes.fromhex("ec172b93ad5e563bf4932c70e1245034")
	keyP+= bytes.fromhex("c35467ef2efd4d64ebf819683467e2bf")
	# MESSAGE (length 64 bytes):
	msg  = bytes.fromhex("ddaf35a193617abacc417349ae204131")
	msg += bytes.fromhex("12e6fa4e89a97ea20a9eeee64b55d39a")
	msg += bytes.fromhex("2192992a274fc1a836ba3c23a3feebbd")
	msg += bytes.fromhex("454d4423643ce80e2a9ac94fa54ca49f")
	# SIGNATURE:
	sigt = bytes.fromhex("dc2a4459e7369633a52b1bf277839a00")
	sigt+= bytes.fromhex("201009a3efbf3ecb69bea2186c26b589")
	sigt+= bytes.fromhex("09351fc9ac90b3ecfdfbc7c66431e030")
	sigt+= bytes.fromhex("3dca179c138ac17ad9bef1177331a704")
	TEST_VERIF( 4, keyP, msg, sigt )


	print("\nTEST(s): pass")

