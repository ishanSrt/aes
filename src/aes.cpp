/*
CSE 539 Semester Project 
Group Members: Klowee Malakowsky, Ishan Srivastava
Description: Implementaion of the Advanced Encryption Standard
(Rijndael algorithm)
*/
#include <stdio.h>
#include<stdlib.h>
#include <iostream>
using namespace std;
typedef unsigned char byte;

#define Nb 4
/* Nb is the Number of columns (32-bit words) comprising the State. For this
 standard, Nb = 4. */

#define Nk 4 //?
/* Nk is the Number of 32-bit words comprising the Cipher Key. For this
standard, Nk = 4, 6, or 8 */

#define Nr 10 //?
/* Nr is the Number of rounds, which is a function of Nk and Nb (which is
fixed). For this standard, Nr = 10, 12, or 14. */

// Rcon[] is the round constant word array
//byte key[4][Nk]; 
byte** input;  //should this be an array or 2d array?? 
byte** output; //should this be an array or 2d array?? 

/* Function Declarations*/
byte** AddRoundKey(byte** s, byte** w, int round);
byte** ShiftRows(byte** s);
byte** InvShiftRows(byte** s);
byte** SubBytes(byte** s);
byte** InvSubBytes(byte** s);
byte** MixColumns(byte** s);
byte** InvMixColumns(byte** s);
byte* SubWord(byte* w[]);
byte* RotWord(byte* w);
void keyExpansion(byte** key, byte** w);
byte** encrypt(byte** in, byte** out, byte** w);
byte** invCipher(byte** in, byte** out, byte** w);


byte** AddRoundKey(byte** s, byte** w, int round) { //w[4][?]
// Transformation in the Cipher and Inverse Cipher in which a 
// Round Key equals the size of the State (i.e., for Nb = 4, the Round
// Key length equals 128 bits/16 bytes). uses xor ^
	int l = round * Nb;
	byte** keyAddedState;

	for(int i = 0; i < 4; i ++)
	{
		for(int j = 0; j < 4; j++)
		{
			keyAddedState[j][i] = s[j][i] ^ w[j][l+i];
		}
	}
	//not really sure on w
	return keyAddedState;
}

byte** ShiftRows(byte** s){
// Transformation in the Cipher that processes the State by cyclically
// shifting the last three rows of the State by different offsets. 

	byte** temp; //declare a temp array to hold all the original values of s
	for(int i = 0; i < 4; i++) //initalize temp
	{
		for(int j = 0; j < 4; j++)
		{
			temp[i][j] = s[i][j];
		}
	}

	for(int i = 1; i < 4; i++) //shift the rows
	{
		for(int j = i; j > 0; j--) 
		{
			s[i][0] = temp[i][1]; //slide the second byte to the first
			s[i][1] = temp[i][2]; //slide third byte to the second
			s[i][2] = temp[i][3]; //slide the last byte to the third
			s[i][3] = temp[i][0]; //set the last byte to the first 
			//since Nb will always be 4 I used numbers, could also use Nb
			//to find the correct column 
		}
	}
	return s;
}

byte** InvShiftRows(byte** s) {
// Transformation in the Inverse Cipher that is the inverse of
// ShiftRows().
	byte** temp; //declare a temp array to hold all the original values of s
	for(int i = 0; i < 4; i++) //initalize temp
	{
		for(int j = 0; j < 4; j++)
		{
			temp[i][j] = s[i][j];
		}
	}

	for(int i = 1; i < 4; i++) //shift the rows
	{
		for(int j = i; j > 0; j--) 
		{
			s[i][0] = temp[i][3]; //slide the last byte back to the first
			s[i][1] = temp[i][0]; //slide first byte back to the second
			s[i][2] = temp[i][1]; //slide the second byte back to the third
			s[i][3] = temp[i][2]; //set the third byte back to the first 
			//since Nb will always be 4 I used numbers, could also use Nb
			//to find the correct column 
		}
	}
	return s;

}


byte** SubBytes(byte** s) {
// Transformation in the Cipher that processes the State using a nonlinear byte substitution table (S-box) that operates on each of the
// State bytes independently.
	byte sBox[16][16] = {  //double check this is comletely correct..
		{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
		{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
		{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
		{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
		{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
		{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
		{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
		{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
		{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
		{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
		{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
		{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
		{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
		{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
		{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
		{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
	};
	byte valueRow;
	byte valueCol;
	byte sixteen = 0x10;
	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 4; j++)
		{
			//need to get the first 4 bits and second 4 bits
			valueRow = (s[i][j]) / sixteen;
			valueCol = (s[i][j]) % sixteen;
			s[i][j] = sBox[valueRow][valueCol];
		}
	}
	return s;
}

byte** InvSubBytes(byte** s) {
// Transformation in the Inverse Cipher that is the inverse of
// SubBytes(). 
}


byte** MixColumns(byte** s) {
// Transformation in the Cipher that takes all of the columns of the
// State and mixes their data (independently of one another) to
// produce new columns. 
	byte** mixedState;

	byte a[4][4] = {
		{0x02, 0x03, 0x01, 0x01},
		{0x01, 0x02, 0x03, 0x01},
		{0x01, 0x01, 0x02, 0x03},
		{0x03, 0x01, 0x01, 0x02}
	};

	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 4; j++)
		{
			mixedState[j][i] = (a[i][0] * s[0][i]) ^ (a[i][1] * s[1][i]) ^ (a[i][2] * s[2][i]) ^ (a[i][3] * s[3][i]);
		}

	}
	return mixedState;
}

byte** InvMixColumns(byte** s){
// Transformation in the Inverse Cipher that is the inverse of
// MixColumns(). 
	byte** mixedState;

	byte a[4][4] = {
		{0x0e, 0x0b, 0x0d, 0x09},
		{0x09, 0x0e, 0x0b, 0x0d},
		{0x0d, 0x09, 0x0e, 0x0b},
		{0x0b, 0x0d, 0x09, 0x0e}
	};

	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 4; j++)
		{
			mixedState[j][i] = (a[i][0] * s[0][i]) ^ (a[i][1] * s[1][i]) ^ (a[i][2] * s[2][i]) ^ (a[i][3] * s[3][i]);
		}

	}
	return mixedState;
}

byte* SubWord(byte* w[]) {
// Function used in the Key Expansion routine that takes a four-byte
// input word and applies an S-box to each of the four bytes to
// produce an output word.
	byte sBox[16][16] = {  //double check this is comletely correct..
		{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
		{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
		{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
		{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
		{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
		{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
		{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
		{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
		{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
		{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
		{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
		{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
		{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
		{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
		{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
		{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
	};

	byte valueRow;
	byte valueCol;
	byte sixteen = 0x10;
	for(int i = 0; i < 4; i++)
	{
		valueRow = *(w[i]) / sixteen;
		valueCol = *(w[i]) % sixteen;
		w[i] = sBox[valueRow][valueCol];
	}
	return w;

}
byte* RotWord(byte* w) {
// Function used in the Key Expansion routine that takes a four-byte
// word and performs a cyclic permutation. 
	byte* temp[4];
	for(int i =0; i < 4; i++)
	{
		temp[i] = w[i];
	}
	w[0] = temp[1];
	w[1] = temp[2];
	w[2] = temp[3];
	w[3] = temp[0];
	
	return w;

}



void keyExpansion(byte** key, byte** w) //words are 4 bytes  //int Nk
{ //for w each column is a word
/*
KeyExpansion(byte key[4*Nk], word w[Nb*(Nr+1)], Nk) 
begin
	word temp
	i = 0

	while (i < Nk)
		w[i] = word(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3])
		i = i+1
	end while

	i = Nk

	while (i < Nb * (Nr+1)]
		temp = w[i-1]
		if (i mod Nk = 0)
			temp = SubWord(RotWord(temp)) xor Rcon[i/Nk]
		else if (Nk > 6 and i mod Nk = 4)
			temp = SubWord(temp)
		end if
		w[i] = w[i-Nk] xor temp
		i = i + 1
	end while
end
 */
	byte* temp; //Nb = 4
	byte Rcon[4][10] = {
		{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		};

	int i = 0;
	while(i < Nk)
	{
		for(int j = 0; j < 4; j++)
		{
			w[i][j] = key[3][j]; //?? says 4 not 3 in sudo code but thats out of bounds?
		}
		i++;
	}
	i = Nk;

	while(i < Nb * (Nr+1))
	{
		temp = w[i-1]; //??
		if(i % Nk == 0)
		{
			temp = *SubWord(temp) ^ *Rcon[i/Nk]; //??
		}
		else if (Nk > 6 && i % Nk == 4)
		{
			temp = SubWord(temp);
		}
		else
		{
			w[i] = *w[i-Nk] ^ *temp;
		}
		i++;
	}

}

byte** encrypt(byte** in, byte** out, byte** w) 
{ //for w each column is a word
	byte** state;
	state = in;
	state = AddRoundKey(state, w, 0); //w[0][Nb-1]

	for(int round = 1; round < (Nr-1); round++)
	{
		state = SubBytes(state);
		state = ShiftRows(state);
		state = MixColumns(state);
		state = AddRoundKey(state, w[round*Nb][(round+1)*Nb-1], round);
	}

	state = SubBytes(state);
	state = ShiftRows(state);
	state = AddRoundKey(state, w[Nr*Nb][(Nr+1)*Nb-1], 0); //not sure on this, what to pass for round?
	return state;
/*
Cipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
begin
	byte state[4,Nb]
	state = in
	AddRoundKey(state, w[0, Nb-1]) // See Sec. 5.1.4

	for round = 1 step 1 to Nr–1
		SubBytes(state) // See Sec. 5.1.1
		ShiftRows(state) // See Sec. 5.1.2
		MixColumns(state) // See Sec. 5.1.3
		AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
	end for

	SubBytes(state)
	ShiftRows(state)
	AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1])
	out = state
end
 */

}

byte** invCipher(byte** in, byte** out, byte** w)
{ //for w each column is a word
	byte** state = malloc(sizeof(byte*) * Nb);
	state = in; //need a loop
	state = AddRoundKey(state, w[Nr*Nb][(Nr+1)*Nb-1], 0); //out of bounds on w? only 4 rows not 17

	for(int round = Nr-1; round > 1; round--)
	{
		state = SubBytes(state);
		state = ShiftRows(state);
		state = MixColumns(state);
		state = AddRoundKey(state, w[round*Nb][(round+1)*Nb-1], round);
	}

	state = SubBytes(state);
	state = ShiftRows(state);
	state = AddRoundKey(state, w[0][Nb-1], 0); //not sure on this, what to pass for round?
	
	return state;

/*
InvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
begin
	byte state[4,Nb]
	state = in
	AddRoundKey(state, w[Nr*Nb, (Nr+1)*Nb-1]) // See Sec. 5.1.4

	for round = Nr-1 step -1 downto 1
		InvShiftRows(state) // See Sec. 5.3.1
		InvSubBytes(state) // See Sec. 5.3.2
		AddRoundKey(state, w[round*Nb, (round+1)*Nb-1])
		InvMixColumns(state) // See Sec. 5.3.3
	end for
	
	InvShiftRows(state)
	InvSubBytes(state)
	AddRoundKey(state, w[0, Nb-1])
	out = state
end
*/

//OR

/*
EqInvCipher(byte in[4*Nb], byte out[4*Nb], word w[Nb*(Nr+1)])
{same as above}

For the Equivalent Inverse Cipher, the following pseudo code is added at
the end of the Key Expansion routine (Sec. 5.2):

for i = 0 step 1 to (Nr+1)*Nb-1
	dw[i] = w[i]
end for

for round = 1 step 1 to Nr-1
	InvMixColumns(dw[round*Nb, (round+1)*Nb-1]) // note change of type
end for

Note that, since InvMixColumns operates on a two-dimensional array of bytes
while the Round Keys are held in an array of words, the call to
InvMixColumns in this code sequence involves a change of type (i.e. the
input to InvMixColumns() is normally the State array, which is considered
to be a two-dimensional array of bytes, whereas the input here is a Round
Key computed as a one-dimensional array of words).
 */
}





