/**********************************************************************
CSE 539 Semester Project 
Group Members: Klowee Malakowsky, Ishan Srivastava
Description: Implementaion of the Advanced Encryption Standard
(Rijndael algorithm)
*************************************************************************/

#include "aes.h"
#define Nb 4 //Nb is the Number of columns (32-bit words) comprising the State. 
//For this standard, Nb = 4.
int Nk; //Nk is the Number of 32-bit words comprising the Cipher Key.
//For this standard, Nk = 4, 6, or 8
int Nr; //Nr is the Number of rounds, which is a function of Nk and Nb. 
//For this standard, Nr = 10, 12, or 14. 

//**************************************************************************
// Function : ShiftRows
// Takes a double pointer, which is the state, and return a double pointer,
// which is the updated state.
//
// Description: Part of the transformation in the cipher that shifts the 
// last three rows of the state by different offsets.
//**************************************************************************
byte** ShiftRows(byte** s)
{
	byte** temp = new byte*[4]; //declare a temp array to hold all the original values of s
	//Allocate array (size 4) of byte pointers (rows)
	for(int i = 0; i < 4; i++)
	{
		temp[i] = new byte[4]; //allocate space for columns
	}

	for(int i = 0; i < 4; i++) 
	{
		for(int j = 0; j < 4; j++)
		{
			temp[i][j] = s[i][j]; //store all of the value of s in temp
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

			temp[i][0] = s[i][0];
			temp[i][1] = s[i][1];  //update the temp array
			temp[i][2] = s[i][2];
			temp[i][3] = s[i][3];
		}
	}
	//free the memory allocated for temp
	return s;
}

//**************************************************************************
// Function : InvShiftRows
// Takes a double pointer, which is the state, and return a double pointer,
// which is the updated state.
//
// Description: Part of the inverse cipher that shifts the last three rows
// of the state by different offsets to "undo" shift rows from the cipher.
//**************************************************************************
byte** InvShiftRows(byte** s) 
{
	byte** temp = new byte*[4]; //temp array to hold the original values of s
	for(int i = 0; i < 4; i++)  //Allocate array (size 4) of byte pointers (rows)
	{
		temp[i] = new byte[4]; //allocate space for columns
	}
	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 4; j++)
		{
			temp[i][j] = s[i][j];   //store all of the value of s in temp
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

			temp[i][0] = s[i][0];
			temp[i][1] = s[i][1];  //update temp
			temp[i][2] = s[i][2];
			temp[i][3] = s[i][3];
		}
	}
	//free the memory allocated for temp
	/*for(int i = 0; i < 4; i++)
	{
		delete[] temp[i];
	}
	delete[] temp;
	*/
	return s;
}

//**************************************************************************
// Function : SubBytes
// Takes a double pointer, which is the state, and return a double pointer,
// which is the updated state.
//
// Description: Part of the transformation in cipher that replaces the values 
// in the state with values from a look up table, s-box.
//**************************************************************************
byte** SubBytes(byte** s) 
{	
	byte valueRow;   	//will be the value of the row to find in s-box
	byte valueCol;		//will be the value of teh column to find in s-box
	byte sixteen = 0x10;

	for(int i = 0; i < 4; i++)  
	{
		for(int j = 0; j < 4; j++)
		{
			valueRow = (s[i][j]) / sixteen; 	//gets the row
			valueCol = (s[i][j]) % sixteen; 	//gets the column
			s[i][j] = sBox[valueRow][valueCol]; //find the value in s-box to substitute
		}
	}
	return s;
}

//**************************************************************************
// Function : InvSubBytes
// Takes a double pointer, which is the state, and return a double pointer,
// which is the updated state.
//
// Description: Part of the inverse cipher that replaces the values 
// in the state with values from a look up table, inverse s-box. This is to 
// "undo" the substition in SubBytes.
//**************************************************************************
byte** InvSubBytes(byte** s) 
{
	byte valueRow;		//will be the value of the row to find in s-box
	byte valueCol;		//will be the value of teh column to find in s-box
	byte sixteen = 0x10;

	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 4; j++)
		{
			valueRow = (s[i][j]) / sixteen;  		//gets the row
			valueCol = (s[i][j]) % sixteen;  		//gets the column
			s[i][j] = invsBox[valueRow][valueCol];	//find the value in inverse s-box to substitute
		}
	}
	return s;
}

//***********************************************************************************
// Function : MixColumns
// Takes a double pointer, which is the state, and return a double pointer,
// which is the updated state.
//
// Description: Part of the transformation in the cipher that takes all of
// the columns in the state and independently mixes the data to produce new columns.
// Uses look up tables for multiplication.
//************************************************************************************
byte** MixColumns(byte** s) 
{
	byte** temp = new byte*[4]; //allocate memory for pointer array
	for(int i = 0; i < 4; i ++)
	{
		temp[i] = new byte[4]; //allocate memory for columns 
	}

	//{0x02, 0x03, 0x01, 0x01} 
	//{0x01, 0x02, 0x03, 0x01}      'a' : matrix to multiply by
	//{0x01, 0x01, 0x02, 0x03}
	//{0x03, 0x01, 0x01, 0x02}

	byte sixteen = 0x10;
	byte zero, one, two, three; 

	for(int i = 0; i < 4; i++) //column
	{
		for(int j = 0; j < 4; j++)  //row
		{ //check which row of 'a' to multiply with and calculate the values using look up tables
			if(j == 0){
				zero = mult2[s[0][i]/sixteen][s[0][i]%sixteen];
				one = mult3[s[1][i]/sixteen][s[1][i]%sixteen];
				two = s[2][i];
				three = s[3][i];
			}
			else if(j == 1)
			{
				zero = s[0][i];
				one = mult2[s[1][i]/sixteen][s[1][i]%sixteen];
				two = mult3[s[2][i]/sixteen][s[2][i]%sixteen];
				three = s[3][i];
			}
			else if(j == 2)
			{
				zero = s[0][i];
				one = s[1][i];
				two = mult2[s[2][i]/sixteen][s[2][i]%sixteen];
				three = mult3[s[3][i]/sixteen][s[3][i]%sixteen];
			}
			else
			{
				zero = mult3[s[0][i]/sixteen][s[0][i]%sixteen];
				one = s[1][i];
				two = s[2][i];
				three = mult2[s[3][i]/sixteen][s[3][i]%sixteen];
			}	
			temp[j][i] = (zero ^ one ^ two ^ three); //xor the values together 
		}
	}
/*
	for(int i = 0; i < 4; i++)
	{			
		for(int j = 0; j < 4; j++)
		{
			s[i][j] = temp[i][j];
		}
	}*/

	//delete temp
	return temp;
}

//***********************************************************************************
// Function : InvMixColumns
// Takes a double pointer, which is the state, and return a double pointer,
// which is the updated state.
//
// Description: Part of the inverse cipher that takes all of the columns in the state 
// and independently mixes the data to produce new columns that "undo" MixColumns.
// Uses look up tables for multiplication.
//************************************************************************************
byte** InvMixColumns(byte** s)
{ 
	byte** temp = new byte*[4]; //Allocate array (size 4) of byte pointers (rows);
	for(int i = 0; i < 4; i++)
	{
		temp[i] = new byte[4]; //allocate space for columns
	}
	
	//{0x0e, 0x0b, 0x0d, 0x09}        0x0b = 11   0x0d = 13   0x0e = 14
	//{0x09, 0x0e, 0x0b, 0x0d}
	//{0x0d, 0x09, 0x0e, 0x0b}			'a' : matrix to multiply by
	//{0x0b, 0x0d, 0x09, 0x0e}
	byte sixteen = 0x10;
	byte zero, one, two, three;
	for(int i = 0; i < 4; i++) //column
	{
		for(int j = 0; j < 4; j++)  //row
		{ //check which row of 'a' to multiply with and calculate the values using look up tables
			if(j == 0){
				zero = multE[s[0][i]/sixteen][s[0][i]%sixteen];
				one = multB[s[1][i]/sixteen][s[1][i]%sixteen];
				two = multD[s[2][i]/sixteen][s[2][i]%sixteen];
				three = mult9[s[3][i]/sixteen][s[3][i]%sixteen];
			}
			else if(j == 1)
			{
				zero = mult9[s[0][i]/sixteen][s[0][i]%sixteen];
				one = multE[s[1][i]/sixteen][s[1][i]%sixteen];
				two = multB[s[2][i]/sixteen][s[2][i]%sixteen];
				three = multD[s[3][i]/sixteen][s[3][i]%sixteen];
			}
			else if(j == 2)
			{
				zero = multD[s[0][i]/sixteen][s[0][i]%sixteen];
				one = mult9[s[1][i]/sixteen][s[1][i]%sixteen];
				two = multE[s[2][i]/sixteen][s[2][i]%sixteen];
				three = multB[s[3][i]/sixteen][s[3][i]%sixteen];
			}
			else
			{
				zero = multB[s[0][i]/sixteen][s[0][i]%sixteen];
				one = multD[s[1][i]/sixteen][s[1][i]%sixteen];
				two = mult9[s[2][i]/sixteen][s[2][i]%sixteen];
				three = multE[s[3][i]/sixteen][s[3][i]%sixteen];
			}	
			temp[j][i] = (zero ^ one ^ two ^ three); //xor the values together 
		}
	}
	//need to delete s
	return temp;
}

//***********************************************************************************
// Function : AddRoundKey
// Takes a double pointer, which is the state, a double pointer, which is the key
// schedule, and in int, which is the round, and return a double pointer, which is 
// the updated state.
//
// Description: Part of the transformation in the cipher and the inverse cipher that 
// takes a round key that is the same size as the state and XORs them together. The 
// round key is generated during the key expansion.
//************************************************************************************
byte** AddRoundKey(byte** s, byte** w, int round) 
{
	for(int i = 0; i < 4; i ++)
	{
		for(int j = 0; j < 4; j++)
		{
			s[i][j] = s[i][j] ^ w[i][4*round+j]; //get the columns for the correct round
		}
	}
	return s;
}

//***********************************************************************************
// Function : xtime
// Takes a byte to multiple with polynomial x and and returns the new byte.
//
// Description: Used by Rcon to perform multiplication polynomial x. Implimented at
// byte level with a left shift and bitwise XOR with 0x1b
//************************************************************************************
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

//***********************************************************************************
// Function : xtime
// Takes a byte pointer and int and returns a byte pointer, rcon.
//
// Description: Used by the KeyExpansion. Rcon generate the round constant rcon.
//************************************************************************************
byte* Rcon(byte* a, int n)
{
	byte c = 1;
	for(int i=1; i<n; i++)
	{
		c = xtime(c);
	}
	a[0] = c;
	a[1] = 0;
	a[2] = 0;
	a[3] = 0;

	return a;
}


//***********************************************************************************
// Function : SubWord
// Takes a byte pointer w, which is a word, and returns the updated word.
//
// Description: Used in KeyExpansion, takes a four byte input (word) and uses the s-box
// to substitute the values of each of the four bytes to produce a new word. 
//************************************************************************************
byte* SubWord(byte* w) 
{
	byte valueRow;   
	byte valueCol;
	byte sixteen = 0x10;
	for(int i = 0; i < 4; i++)
	{
		valueRow = (w[i]) / sixteen;  		//find the row
		valueCol = (w[i]) % sixteen;		//find the value
		w[i] = sBox[valueRow][valueCol];	//find the value in s-box to replace the original value
	}
	return w;
}

//***********************************************************************************
// Function : RotWord
// Takes a byte pointer w, which is a word, and returns the updated word.
//
// Description: Used in KeyExpansion, takes a four byte input (word) and performs a
// cyclic permutation. 
//************************************************************************************
byte* RotWord(byte* w) 
{
	byte* temp = new byte[4]; //allocate memory for  temp 
	for(int i =0; i < 4; i++)
	{
		temp[i] = w[i]; //assign the original values of w to temp
	}
	w[0] = temp[1];  //rotate the value in w
	w[1] = temp[2];
	w[2] = temp[3];
	w[3] = temp[0];
	return w;
}

//*************************************************************************************
// Function : KeyExpansion
// Takes a byte pointer key, which is the random key, a double pointer w, which will be
// the key schedule, and returns the generated key schedule.
//
// Description: Uses a smaller (128, 192, 256) bit key to generate a larger key with a
// total of Nb(Nr + 1) words and return this generated key schedule.
//***************************************************************************************
byte** KeyExpansion(byte* key, byte** w, int Nk) // generates a total of Nb(Nr + 1) words
{ 

	byte* temp = new byte[4]; 	//allocate memory for a temp word
	byte* rcon = new byte[4];	//allocate memory for the round contsant

	for(int i = 0; i < Nk; i++)  //fill the first 4 columns of w with the random key values
	{
		for(int j = 0; j < 4; j++)
		{
			w[j][i] = key[4*i+j];
		}
	}
	
	for(int i = Nk; i < 4 * Nb * (Nr+1); i++)  //fill the remaining columns 
	{
		if(i == (Nb*(Nr+1)))		//check to see if the number of rounds has been reached
		{
			break;
		}
		temp[0] = w[0][i-1];   	//set temp to the word in the previous column,
		temp[1] = w[1][i-1];	//the perviously generated word
		temp[2] = w[2][i-1];
		temp[3] = w[3][i-1];

		if(i % Nk == 0)    //check if the round is a multiple of 4
		{
			temp = RotWord(temp);
			temp = SubWord(temp);
			rcon = Rcon(rcon, i/(Nk));

			temp[0] = temp[0] ^ rcon[0];
			temp[1] = temp[1] ^ rcon[1];
			temp[2] = temp[2] ^ rcon[2];
			temp[3] = temp[3] ^ rcon[3];
		}
		else if (Nk > 6 && i % Nk == 4)   	//if using a 256 bit key  Nk would be 8
		{									//check if the round % 8 is 4
			temp = SubWord(temp);
		}

		w[0][i] = w[0][i-Nk] ^ temp[0];  //fill the column with the key that was generated
		w[1][i] = w[1][i-Nk] ^ temp[1];
		w[2][i] = w[2][i-Nk] ^ temp[2];
		w[3][i] = w[3][i-Nk] ^ temp[3];	
	}
	//delete temp and rcon
	return w;
}

//*************************************************************************************
// Function : blockToState
// Takes a byte pointer, such as the input array, and returns a matrix 
// (double pointer), such as the state.
//
// Description: 
// Takes a byte pointer, such as the input array, and changes it into a matrix 
// (double pointer), such as the state.
//***************************************************************************************
byte** blockToState(byte* inout)
{
	byte** state = new byte*[4]; //Allocate array (size 4) of byte pointers (rows)
	for(int i = 0; i < 4; i++)
	{
		state[i] = new byte[4]; //allocate space for columns
	}

	for(int i = 0; i < 4; i++) //convert array into matrix
	{
		for(int j=0; j<4; j++)
		{
			state[i][j] = inout[i+4*j];
		}
	}
	return state;
}

//*************************************************************************************
// Function : blockToState
// Takes a double byte pointer, such as the state and returns .byte pointer, such as 
// the input array
//
// Description: 
// Takes a byte pointer, such as the input array, and changes it into a matrix 
// (double pointer), such as the state.
//***************************************************************************************
byte* stateToBlock(byte** state)
{
	byte *inout = new byte[4*Nb]; //Allocate array (size 4) of byte pointers (rows)
	for(int i = 0; i < 4; i++)
	{
		for(int j = 0; j < 4; j++)
		{
			inout[i*4+j] = state[j][i]; //convert matrix into array
		}
	}
	return inout;
}

//***********************************************************************************
// Function : Cipher
// Takes a byte pointer, the input message, and a double pointer, the key schedule, 
// and return a double byte pointer, which is the cipher text.
//
// Description: Takes a message (128 bits) and performs multiple different rounds of 
// different transformations to create a cipher text. Can use keys of length 128, 
// 192, or 256 bits.
//************************************************************************************
byte* Cipher(byte* in, byte** w) 
{
	byte** state = new byte*[4]; //Allocate array (size 4) of byte pointers (rows)
	for(int i = 0; i < 4; i++)
	{
		state[i] = new byte[4]; //allocate space for columns
	}

	state = blockToState(in);				//make the input into a matrix
	state = AddRoundKey(state, w, 0); 		//first call to add round key

	for(int round = 1; round <= (Nr-1); round++)  //loop through rounds
	{
		state = SubBytes(state);
		state = ShiftRows(state);
		state = MixColumns(state);
		state = AddRoundKey(state, w, round); 
	}

	state = SubBytes(state);  			//the last round
	state = ShiftRows(state);
	state = AddRoundKey(state, w, Nr); 
	return stateToBlock(state);			//put matrix back into array for output
}

//***********************************************************************************
// Function : InvCipher
// Takes a byte pointer, the cipher text, and a double pointer, the key schedule, 
// and return a double byte pointer, which is the original message.
//
// Description: Takes a cipher text (128 bits) and performs multiple different rounds of 
// different transformations to "undo" the cipher and return the original message. 
// Can use keys of length 128, 192, or 256 bits.
//************************************************************************************
byte* InvCipher(byte* in, byte** w)
{
	byte** state = new byte*[4]; //allocate memory for the state
	for(int i = 0; i < 4; i++)
	{
		state[i] = new byte[4]; //allocate space for columns
	}
	state = blockToState(in);   	//make the input into a matrix
	state = AddRoundKey(state, w, Nr);  

	for(int round = Nr-1; round > 0; round--) //perform rounds
	{
		state = InvShiftRows(state);
		state = InvSubBytes(state);
		state = AddRoundKey(state, w , round);
		state = InvMixColumns(state);
	}

	state = InvShiftRows(state);  //the last round
	state = InvSubBytes(state);
	state = AddRoundKey(state, w, 0);
	return stateToBlock(state);  		//put matrix back into array for output
}

int main()
{
	byte* input = new byte[4*Nb];  //message to be encrypted
	byte* output = new byte[4*Nb]; //encrypted message
	int keyLen;
	cout << "Enter key length 128, 192, or 256\n";
	cin >> keyLen;
	switch(keyLen)
	{
		case 128:
			Nk = 4;   	// Nk (key length 128, 192, 256) = 4, 6, 8 reflects the number of 32 bit words 
			Nr = 10;	// or the number of columns in the cipher key
			break;		// Nr (number of rounds) depends on key length = 10, 12, 14
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
	byte* key = new byte[Nk*Nb];
	byte** w = new byte*[4]; //allocare memory for rows  (4 bytes)
	for(int i = 0; i < 4; i++) //allocate columns, the number of key expasions
	{
		w[i] = new byte[Nb * (Nr+1)]; //key schedule for 128 its 44
	}
//-----------------TEST-CASES-FROM-STANDARD-----------------------------------------
	//128 bit meesage
	byte message[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	//128 bit key
	byte cipherKey[Nk*Nb] =  {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	
	//192 bit key
	//byte cipherKey[Nk*Nb] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
	
	//256 bit key
	//byte cipherKey[Nk*Nb] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
	
	//byte message[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	//test 128
	//byte cipherKey[Nk*Nb] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

	//tes 192
	//byte cipherKey[Nk*Nb] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};

	//test 256
	//byte cipherKey[Nk*Nb] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}; 
//--------------------------END-TESTS----------------------------------------------------
	key = cipherKey;
	input = message;
	w = KeyExpansion(key, w, Nk); //make the key schedule

	output = Cipher(input, w); //encrypt the message

//--------PRINT-CIPHER-TEXT-----------------
	cout << "\nThe cipher text is : \n";
	for(int i = 0; i < 16; i++)
	{
		cout << hex << +output[i] << " ";
	}
//-------------------------------------------

	output = InvCipher(output, w);  //decrypt the message

//------PRINT-ORIGINAL-MESSAGE------------------
	cout << "\n\nThe original message was : \n";
	for(int i = 0; i < 16; i++)
	{
		cout << hex << +output[i] << " ";
	}
	cout << "\n";
//-----------------------------------------------

	return 0;
}





