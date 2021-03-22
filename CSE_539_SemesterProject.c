/*
CSE 539 Semester Project 
Group Members: Klowee Malakowsky, Ishan Srivastava
Description: Implementaion of the Advanced Encryption Standard
(Rijndael algorithm)
*/

int Nb = 4;
// Nb is the Number of columns (32-bit words) comprising the State. For this
// standard, Nb = 4. 

int Nk = 4; //?
// Nk is the Number of 32-bit words comprising the Cipher Key. For this
// standard, Nk = 4, 6, or 8

int Nr = 10; //?
// Nr is the Number of rounds, which is a function of Nk and Nb (which is
// fixed). For this standard, Nr = 10, 12, or 14.

// Rcon[] is the round constant word array
//byte key[4][Nk]; 
byte input[4][Nb];  //should this be an array or 2d array?? 
byte output[4][Nb]; //should this be an array or 2d array?? 


byte[][] AddRoundKey(byte s[4][Nb], word w[][], int round) {
// Transformation in the Cipher and Inverse Cipher in which a 
// Round Key equals the size of the State (i.e., for Nb = 4, the Round
// Key length equals 128 bits/16 bytes). uses xor ^
	int l = round * Nb;
	byte keyAddedState[4][Nb];

	for(int i = 0; i < 4; i ++)
	{
		for(int j = 0; j < 4; j++)
		{
			keyAddedState[j][i] = s[j][i] ^ w[j][l+i];
		}
	}
	//not really sure on w

}

byte[][] ShiftRows(byte s[4][Nb]){
// Transformation in the Cipher that processes the State by cyclically
// shifting the last three rows of the State by different offsets. 

	byte temp[4][Nb]; //declare a temp array to hold all the original values of s
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

byte[][] InvShiftRows(byte s[4][Nb]) {
// Transformation in the Inverse Cipher that is the inverse of
// ShiftRows().
	byte temp[4][Nb]; //declare a temp array to hold all the original values of s
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


byte[][] SubBytes(byte s[4][Nb]) {
// Transformation in the Cipher that processes the State using a nonlinear byte substitution table (S-box) that operates on each of the
// State bytes independently.
}

byte[][] InvSubBytes(byte s[4][Nb]) {
// Transformation in the Inverse Cipher that is the inverse of
// SubBytes(). 
}


byte[][] MixColumns(byte s[4][Nb]) {
// Transformation in the Cipher that takes all of the columns of the
// State and mixes their data (independently of one another) to
// produce new columns. 
	byte mixedState[4][Nb];

	byte a[4][4] = {
		{0x02, 0x03, 0x01, 0x01}
		{0x01, 0x02, 0x03, 0x01}
		{0x01, 0x01, 0x02, 0x03}
		{0x03, 0x01, 0x01, 0x02}
	}

	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 4; j++)
		{
			mixedState[j][i] = (a[i][0] * s[0][i]) ^ (a[i][1] * s[1][i]) ^ (a[i][2] * s[2][i]) ^ (a[i][3] * s[3][i]);
		}

	}
	return mixedState
}

byte[][] InvMixColumns(byte s[4][Nb]){
// Transformation in the Inverse Cipher that is the inverse of
// MixColumns(). 
	byte mixedState[4][Nb];

	byte a[4][4] = {
		{0x0e, 0x0b, 0x0d, 0x09}
		{0x09, 0x0e, 0x0b, 0x0d}
		{0x0d, 0x09, 0x0e, 0x0b}
		{0x0b, 0x0d, 0x09, 0x0e}
	}

	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 4; j++)
		{
			mixedState[j][i] = (a[i][0] * s[0][i]) ^ (a[i][1] * s[1][i]) ^ (a[i][2] * s[2][i]) ^ (a[i][3] * s[3][i]);
		}

	}
	return mixedState
}

RotWord() {
// Function used in the Key Expansion routine that takes a four-byte
// word and performs a cyclic permutation. 
}

SubWord() {
// Function used in the Key Expansion routine that takes a four-byte
// input word and applies an S-box to each of the four bytes to
// produce an output word.
}

keyExpansion()
{
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
}

byte[][] encrypt(byte in[4][Nb], byte out[4][Nb], word w[Nb][(Nr + 1)]) 
{ 
	byte state[4][Nb];
	state = in;
	state = AddRoundKey(state, w[0][Nb-1], 0)

	for(int round = 1; round < (Nr-1); round++)
	{
		state = SubBytes(state);
		state = ShiftRows(state);
		state = MixColumns(state);
		state = AddRoundKey(state, w[round*Nb][(round+1)*Nb-1], round);
	}

	state = SubBytes(state);
	state = ShiftRows(state);
	state = AddRoundKey(state, w[round*Nb][(Nr+1)*Nb-1], 0; //not sure what the "round" is
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

invCipher(byte in[4][Nb], byte out[4][Nb], word w[Nb*(Nr+1)])
{
	byte state[4][Nb];
	state = in;
	state = AddRoundKey(state, w[Nr*Nb][(Nr+1)*Nb-1], 0);

	for(int round = Nr-1; round > 1; round--)
	{
		state = SubBytes(state);
		state = ShiftRows(state);
		state = MixColumns(state);
		state = AddRoundKey(state, w[round*Nb][(round+1)*Nb-1], round);
	}

	state = SubBytes(state);
	state = ShiftRows(state);
	state = AddRoundKey(state, w[0][Nb-1], 0); //not sure what the "round" is


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
EqInvCipher(byte in[4*Nb], byte out[4*Nb], word dw[Nb*(Nr+1)])
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





