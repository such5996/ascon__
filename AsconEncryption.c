
/*Implementation of Lightweight Cryptography - ASCON*/

#include<stdio.h>
typedef unsigned __int64 bit64; //one register of 64 bit

bit64 state[5] = { 0 }, t[5] = { 0 }; //total 5 registers are there

bit64 constants[16] = { 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69,
0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f };

//rotation operation
bit64 rotate(bit64 x, int l) { 
	bit64 temp;
	temp = (x >> l) ^ (x << (64 - 1)); // shift l bit right (left l bit become zero), therefore exor (leftshift 64-l) bit
	return temp;
}

// Linear layer - exor with itself after a rotation
void linear(bit64 state[5]) { 
	bit64 tmp0, tmp1;
	tmp0 = rotate(state[0], 19);
	tmp1 = rotate(state[0], 28);
	state[0] ^= tmp0 ^ tmp1;		//register 1
	tmp0 = rotate(state[1], 61);
	tmp1 = rotate(state[1], 39);
	state[1] ^= tmp0 ^ tmp1;		//register 2		
	tmp0 = rotate(state[2], 1);
	tmp1 = rotate(state[2], 6);
	state[2] ^= tmp0 ^ tmp1;		//register 3
	tmp0 = rotate(state[3], 10);
	tmp1 = rotate(state[3], 17);
	state[3] ^= tmp0 ^ tmp1;		//register 4
	tmp0 = rotate(state[4], 7);
	tmp1 = rotate(state[4], 41);
	state[4] ^= tmp0 ^ tmp1;		//register 5

}

//bit slicing ( useful against side channel attacks)
void s_Box (bit64 x[5]) { 
	x[0] ^= x[4]; x[4] ^= x[3]; x[2] ^= x[1];
	t[0] = x[0]; t[1] = x[1]; t[2] = x[2]; t[3] = x[3]; t[4] = x[4];
	t[0] = ~t[0]; t[1] = ~t[1]; t[2] = ~t[2]; t[3] = ~t[3]; t[4] = ~t[4];
	t[0] &= x[1]; t[1] &= x[2]; t[2] &= x[3]; t[3] &= x[4]; t[4] &= x[0];
	x[0] ^= t[1]; x[1] ^= t[2]; x[2] ^= t[3]; x[3] ^= t[4]; x[4] ^= x[0];
	x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] ^= ~x[2];

}

//round constant addition
void add_constant(bit64 state[5], int i, int a) { 
	state[2] = state[2] ^ constants[12 - a + 1];
}

//permutation P-box
void p_Box(bit64 state[5], int a) { //permutation
	for (int i = 0; i < a; i++) {
		add_constant(state, i, a); //round constant addition
		s_Box(state); //substitution layer with 5 bit s box
		linear(state); // Linear layer with 64 bit diffusion function
	}
}

void initialization(bit64 state[5], bit64 key[2]) {
	p_Box(state, 12);
	state[3] ^= key[0];
	state[4] ^= key[1];
}

bit64 print_state(bit64 state[5]) {
	printf("States : \n");
	for (int i = 0; i < 5; i++)
		printf("%016I64x\n", state[i]); //see an hexadecimal in visual studio
}

void encryption(bit64 state[5], int length, bit64 plaintext[], bit64 ciphertext[]) {
	ciphertext[0] = plaintext[0] ^ state[0];
	for (int i = 1; i < length; i++) {
		p_Box(state, 6);
		ciphertext[i] = plaintext[i] ^ state[0];
		state[0] = ciphertext[i];
	}
}

void finalization(bit64 state[5], bit64 key[2]) {
	state[0] ^= key[0];
	state[1] ^= key[1];
	p_Box(state, 12);

}

void main() {
	bit64 nonce[2] = { 0 };
	bit64 key[2] = { 0 };
	bit64 IV = 0x80400c0600000000;
	bit64 plaintext[] = { 0x123456790abcdef, 0x82187 };
	bit64 ciphertext[10] = { 0 };
	state[0] = IV;
	state[1] = key[0];
	state[2] = nonce[0];
	state[4] = nonce[1]; 
	initialization(state, key);
	print_state(state);
	printf("Plaintext : %016I64x %016I64x\n", plaintext[0], plaintext[1]);
	encryption(state, 2, plaintext, ciphertext);
	printf("Ciphertext After Encryption : %016I64x %016I64x\n", ciphertext[0], ciphertext[1]);
	finalization(state, key);
	printf("Tag After Encryption : %016I64x %016I64x\n", state[3], state[4]);
}
