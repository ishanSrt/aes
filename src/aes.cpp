/**********************************************************************
CSE 539 Semester Project 
Group Members: Klowee Malakowsky, Ishan Srivastava
Description: Implementaion of the Advanced Encryption Standard
(Rijndael algorithm)
*************************************************************************/

#include "aes.h"
//#define Nb 4 //Nb is the Number of columns (32-bit words) comprising the State. 
//For this standard, Nb = 4.
//int Nk; //Nk is the Number of 32-bit words comprising the Cipher Key.
//For this standard, Nk = 4, 6, or 8
//int Nr; //Nr is the Number of rounds, which is a function of Nk and Nb. 
//For this standard, Nr = 10, 12, or 14. 

//**************************************************************************
// Function : ShiftRows
// Takes a double pointer, which is the state, and return a double pointer,
// which is the updated state.
//
// Description: Part of the transformation in the cipher that shifts the 
// last three rows of the state by different offsets.
//**************************************************************************

Aes::Aes(int keyLen)
{
	this->Nb = 4;
	switch (keyLen)
	{
		case 128:
			Nk = 4;	 // Nk (key length 128, 192, 256) = 4, 6, 8 reflects the number of 32 bit words
			Nr = 10; // or the number of columns in the cipher key
			break;	 // Nr (number of rounds) depends on key length = 10, 12, 14
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
}

int Aes::getNk()
{
	return Nk;
}

int Aes::getNr()
{
	return Nr;
}

int Aes::getNb()
{
	return Nb;
}

byte** Aes::ShiftRows(byte** s)
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
byte **Aes::InvShiftRows(byte **s)
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
byte **Aes::SubBytes(byte **s)
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
byte **Aes::InvSubBytes(byte **s)
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
byte **Aes::MixColumns(byte **s)
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
byte **Aes::InvMixColumns(byte **s)
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
byte **Aes::AddRoundKey(byte **s, byte **w, int round)
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
byte Aes::xtime(byte b) // multiplication by x
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
byte *Aes::Rcon(byte *a, int n)
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
byte *Aes::SubWord(byte *w)
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
byte *Aes::RotWord(byte *w)
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
byte **Aes::KeyExpansion(byte *key, byte **w) // generates a total of Nb(Nr + 1) words
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
byte **Aes::blockToState(byte *inout)
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
byte *Aes::stateToBlock(byte **state)
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
byte *Aes::Cipher(byte *in, byte **w)
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
byte *Aes::InvCipher(byte *in, byte **w)
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

string blockToReadable(byte* inout)
{
	stringstream stream;
	for(int i = 0; i < 16; i++)
	{
		if(i!=15)
		{
			stream << hex << (int)inout[i] << " ";
		}
		else
		{
			stream << hex << (int)inout[i];
		}
	}
	string result( stream.str() );
	return result;
}







