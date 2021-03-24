/*
CSE 539 Semester Project 
Group Members: Klowee Malakowsky, Ishan Srivastava
Description: Implementaion of the Advanced Encryption Standard
(Rijndael algorithm)
*/

#include "aes.h"

#define Nb 4
/* Nb is the Number of columns (32-bit words) comprising the State. 
For this standard, Nb = 4. */

int Nk;
/* Nk is the Number of 32-bit words comprising the Cipher Key.
For this standard, Nk = 4, 6, or 8 */

int Nr;
/* Nr is the Number of rounds, which is a function of Nk and Nb (which is
fixed). For this standard, Nr = 10, 12, or 14. */

// Rcon[] is the round constant word array
//byte key[4][Nk]; 



byte** input;  //should this be an array or 2d array?? 
byte** output; //should this be an array or 2d array?? 

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
			s[i][j] = invsBox[valueRow][valueCol];
		}
	}
	return s;

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

byte xtime(byte b) // multiplication by x
{
	if((b>>7) == 1)
	{
		return (b<<1) ^ 0x1b;
	}
	else
	{
		return (b<<1);
	}
}

void Rcon(byte* a, int n)
{
	byte c = 1
	for (int i=1; i<n; i++)
	{
		c = xtime(c);
	}
	a[0] = c;
	a[1] = 0;
	a[2] = 0;
	a[3] = 0;
}

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

void SubWord(byte* w) {
// Function used in the Key Expansion routine that takes a four-byte
// input word and applies an S-box to each of the four bytes to
// produce an output word.

	byte valueRow;
	byte valueCol;
	byte sixteen = 0x10;
	for(int i = 0; i < 4; i++)
	{
		valueRow = (w[i]) / sixteen;
		valueCol = (w[i]) % sixteen;
		w[i] = sBox[valueRow][valueCol];
	}
}


void RotWord(byte* w) {
// Function used in the Key Expansion routine that takes a four-byte
// word and performs a cyclic permutation. 
	byte temp[4];
	for(int i =0; i < 4; i++)
	{
		temp[i] = w[i];
	}
	w[0] = temp[1];
	w[1] = temp[2];
	w[2] = temp[3];
	w[3] = temp[0];
}

// Nk (key length 128, 192, 256) = 4, 6, 8 reflects the number of 32 bit words 
// or the number of columns in the cipher key

// Nr (number of rounds) depends on key length = 10, 12, 14
// Nb = 4

void keyExpansion(byte* key, byte* w, int Nk) // generates a total of Nb(Nr + 1) words
{ //for w each column is a word
	byte* temp = new byte[4];
	byte* rcon = new byte[4];

	int i = 0;
	while(i < 4*Nk)
	{	
		w[i] = key[i];
		i++;
	}
	i = 4*Nk;

	while(i < 4 * Nb * (Nr+1))
	{
		temp[0] = w[i-4];
		temp[1] = w[i-3];
		temp[2] = w[i-2];
		temp[3] = w[i-1];

		if(i/4 % Nk == 0)
		{
			RotWord(temp);
			SubWord(temp);
			Rcon(rcon, i/(Nk*4));
			temp[0] = temp[0] ^ rcon[0];
			temp[1] = temp[1] ^ rcon[1];
			temp[2] = temp[2] ^ rcon[2];
			temp[3] = temp[3] ^ rcon[3];
		}
		else if (Nk > 6 && i/4 % Nk == 4)
		{
			SubWord(temp);
		}
	
		
		w[i] = w[i-4*Nk] ^ temp[0];
    	w[i+1] = w[i-4*Nk+1] ^ temp[1];
    	w[i+2] = w[i-4*Nk+2] ^ temp[2];
    	w[i+3] = w[i-4*Nk+3] ^ temp[3];
		
		i+=4;
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
}

int main()
{
	//REDO
	int keyLen
	cout << "keyLen\n";
	cin >> keyLen;
	switch(keyLen)
	{
		case 128:
			Nk = 4;
			Nr = 10;
			break;
		case 192:
			Nk = 6;
			Nr = 12;
			break;
		case 256:
			Nk = 8;
			Nr = 14;
			break;
		default:
		throw "Incorrect Key Length";
	}

	return 0;
}





