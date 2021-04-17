/**
* CSE 539 Semester Project
*
* Group Members: Klowee Malakowsky, Ishan Srivastava
*
* Implementaion of the Advanced Encryption Standard
* (Rijndael algorithm)
*/

#include "aes.h"
//#define Nb 4 //Nb is the Number of columns (32-bit words) comprising the State.
//For this standard, Nb = 4.
//int Nk; //Nk is the Number of 32-bit words comprising the Cipher Key.
//For this standard, Nk = 4, 6, or 8
//int Nr; //Nr is the Number of rounds, which is a function of Nk and Nb.
//For this standard, Nr = 10, 12, or 14.

Aes::Aes(int keyLen)
{
    this->Nb = 4;
    switch (keyLen)
    {
        case 128:
            Nk = 4;  // Nk (key length 128, 192, 256) = 4, 6, 8 reflects the number of 32 bit words
            Nr = 10; // or the number of columns in the cipher key
            break;   // Nr (number of rounds) depends on key length = 10, 12, 14
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

/**
* Shifts the rows in the state
*
* Used as part of the transformation proccess in the cipher
*
* @param s is the state
* @return the new state after shifting rows
*/
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

/**
* Shifts the rows in the state
*
* Used as part of the transformation proccess in the inverse cipher
*
* @param s is the state
* @return the new state after shifting rows
*/
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

/**
* Substitutes each byte in the state with one from s-box
*
* Used as part of the transformation proccess in the cipher
*
* @param s is the state
* @return the new state after substitions
*/
byte **Aes::SubBytes(byte **s)
{
    byte valueRow;      //will be the value of the row to find in s-box
    byte valueCol;      //will be the value of teh column to find in s-box
    byte sixteen = 0x10;

    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            valueRow = (s[i][j]) / sixteen;     //gets the row
            valueCol = (s[i][j]) % sixteen;     //gets the column
            s[i][j] = sBox[valueRow][valueCol]; //find the value in s-box to substitute
        }
    }
    return s;
}

/**
* Substitutes each byte in the state with one from the inverse s-box
*
* Used as part of the transformation proccess in the inverse cipher
*
* @param s is the state
* @return the new state after substitions
*/
byte **Aes::InvSubBytes(byte **s)
{
    byte valueRow;      //will be the value of the row to find in s-box
    byte valueCol;      //will be the value of teh column to find in s-box
    byte sixteen = 0x10;

    for(int i = 0; i < 4; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            valueRow = (s[i][j]) / sixteen;         //gets the row
            valueCol = (s[i][j]) % sixteen;         //gets the column
            s[i][j] = invsBox[valueRow][valueCol];  //find the value in inverse s-box to substitute
        }
    }
    return s;
}

/**
* Mixes the columns in the state
*
* Used as part of the transformation proccess in the cipher
*
* @param s is the state
* @return the new state after mixing the columns
*/
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

/**
* Mixes the columns in the state
*
* Used as part of the transformation proccess in the inverse cipher
*
* @param s is the state
* @return the new state after mixing columns
*/
byte **Aes::InvMixColumns(byte **s)
{
    byte** temp = new byte*[4]; //Allocate array (size 4) of byte pointers (rows);
    for(int i = 0; i < 4; i++)
    {
        temp[i] = new byte[4]; //allocate space for columns
    }

    //{0x0e, 0x0b, 0x0d, 0x09}        0x0b = 11   0x0d = 13   0x0e = 14
    //{0x09, 0x0e, 0x0b, 0x0d}
    //{0x0d, 0x09, 0x0e, 0x0b}          'a' : matrix to multiply by
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

/**
* XORs a round key from the key schedule with the state
*
* Used as part of the transformation proccess in the cipher and inverse cipher
*
* @param s is the state
* @param w is the key schedule
* @param round is the round number the cipher/inverse cipher is on
* @return the new state after XORing the round key
*/
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

/**
* Multiplies a byte with polynomial x
*
* Multiplication is performed with left shift and bitwise XOR with 0x1b
*
* @param b is the byte to multiply with x
* @return the resulting byte after multiplication with x
*/
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

/**
* Generates round constant
*
* Used during the key expansion process
*
* @param b is a byte pointer
* @param n is the round
* @return the resulting round constant rcon
*/
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

/**
* Uses s-box to substitue values to creale a new word
*
* Used during the key expansion process
*
* @param w is the word
* @return the resulting word after substitution
*/
byte *Aes::SubWord(byte *w)
{
    byte valueRow;
    byte valueCol;
    byte sixteen = 0x10;
    for(int i = 0; i < 4; i++)
    {
        valueRow = (w[i]) / sixteen;        //find the row
        valueCol = (w[i]) % sixteen;        //find the value
        w[i] = sBox[valueRow][valueCol];    //find the value in s-box to replace the original value
    }
    return w;
}

/**
* Performs cyclic permutation
*
* Used during the key expansion process
*
* @param w is the word
* @return the resulting word after cyclic permutation
*/
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

/**
* Generates key schedule from original key for a total of Nb(Nr + 1) words
*
* @param key is the original random key
* @param w is the key schedule
* @param Nk is the number of 4 byte words in the cipher key
* @return the resulting key schedule
*/
byte **Aes::KeyExpansion(byte *key, byte **w) // generates a total of Nb(Nr + 1) words
{

    byte* temp = new byte[4];   //allocate memory for a temp word
    byte* rcon = new byte[4];   //allocate memory for the round contsant

    for(int i = 0; i < Nk; i++)  //fill the first 4 columns of w with the random key values
    {
        for(int j = 0; j < 4; j++)
        {
            w[j][i] = key[4*i+j];
        }
    }

    for(int i = Nk; i < 4 * Nb * (Nr+1); i++)  //fill the remaining columns
    {
        if(i == (Nb*(Nr+1)))        //check to see if the number of rounds has been reached
        {
            break;
        }
        temp[0] = w[0][i-1];    //set temp to the word in the previous column,
        temp[1] = w[1][i-1];    //the perviously generated word
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
        else if (Nk > 6 && i % Nk == 4)     //if using a 256 bit key  Nk would be 8
        {                                   //check if the round % 8 is 4
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

/**
* Takes a byte pointer and makes it into a matrix
*
* @param inout is the byte pointer to change into a matrix
* @return a double byte pointer to the resulting matrix
*/
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

/**
* Takes a matrix, double byte pointer and makes it into a byte array
*
* @param state is the matrix to change into a single array
* @return a byte pointer to the resulting array
*/
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

/**
* Encrypts a 128 bit message
*
* @param in is the message to be encrypted
* @param w is the key schedule
* @return the encrypted message
*/
byte *Aes::Cipher(byte *in, byte **w)
{
    byte** state = new byte*[4]; //Allocate array (size 4) of byte pointers (rows)
    for(int i = 0; i < 4; i++)
    {
        state[i] = new byte[4]; //allocate space for columns
    }

    state = blockToState(in);               //make the input into a matrix
    state = AddRoundKey(state, w, 0);       //first call to add round key

    for(int round = 1; round <= (Nr-1); round++)  //loop through rounds
    {
        state = SubBytes(state);
        state = ShiftRows(state);
        state = MixColumns(state);
        state = AddRoundKey(state, w, round);
    }

    state = SubBytes(state);            //the last round
    state = ShiftRows(state);
    state = AddRoundKey(state, w, Nr);
    return stateToBlock(state);         //put matrix back into array for output
}

/**
* Decrypts a 128 bit message
*
* @param in is the message to be decrypted
* @param w is the key schedule
* @return the decrypted message
*/
byte *Aes::InvCipher(byte *in, byte **w)
{
    byte** state = new byte*[4]; //allocate memory for the state
    for(int i = 0; i < 4; i++)
    {
        state[i] = new byte[4]; //allocate space for columns
    }
    state = blockToState(in);       //make the input into a matrix
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
    return stateToBlock(state);         //put matrix back into array for output
}

/**
* Takes a byte pointer to a block and makes it readable
*
* @param inout is the byte array to make readable (block)
* @param len is the block length
* @return the readable string
*/
string Aes::blockToReadable(byte* inout, int len=16)
{
    stringstream stream;
    for(int i = 0; i < len; i++)
    {
        if(i!=len-1)
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

/**
* Adds a specified amount of padding to a message
*
* @param len is the amount of padding to add
* @param messageLen is the total length of the message to encrypt
* @param input is the message to add padding to
* @return the message with added padding
*/
byte *Aes::addPadding(int len, int messageLen, byte *input)
{
    byte one = 0x01;
    byte padding[len];
    padding[0] = one;
    for(int i=0;i<len-1;i++)
    {
        padding[i+1] = 0x00;
    }
    int inputsize = messageLen;
    int paddedLen = len+inputsize;
    byte* paddedMessage = new byte[paddedLen];

    for(int i=0;i<inputsize;i++)
    {
        paddedMessage[i] = input[i];
    }

    for(int i=0;i<len;i++)
    {
        paddedMessage[i+inputsize] = padding[i];
    }
    return paddedMessage;
}

/**
* Find the amount fo padding to add then calls addPadding
*
* @param input is the message to be encrypted
* @param messageLen is the length of the message
* @return the message with padding added
*/
byte *Aes::getPaddedMessage(byte* input, int messageLen)
{
    int len;
    int inputsize = messageLen;
    if(inputsize%16==0)
    {
        len = 16;
    }
    else
    {
        len = 16-inputsize%16;
    }
    byte* paddedMessage = new byte[len+inputsize];
    paddedMessage = addPadding(len, inputsize, input);

    return paddedMessage;
}

/**
* Encrypt a message using ECB mode
*
* @param input is the message to be encrypted
* @param messageLen is the length of the message being encrypted
* @param key is the randomly generated key
* @return the encrypted message
*/
byte *Aes::encryptECB(byte* input, int messageLen, byte* key)
{
    byte* paddedMessage = getPaddedMessage(input, messageLen);
    int paddedMessageLen = messageLen + 16-messageLen%16;
    byte* output = new byte[paddedMessageLen];

    byte** w = new byte*[4]; //allocate memory for rows  (4 bytes)
    for(int i = 0; i < 4; i++) //allocate columns, the number of key expasions
    {
        w[i] = new byte[Nb * (Nr+1)]; //key schedule for 128 its 44
    }

    w = KeyExpansion(key, w);

    for(int i=0;i<paddedMessageLen/16;i++)
    {
        byte* currentBlock = new byte[16];
        byte* outputBlock = new byte[16];
        for(int j=0;j<16;j++)
        {
            currentBlock[j] = paddedMessage[i*16+j];
        }

        outputBlock = Cipher(currentBlock, w);
        for(int j=0; j<16;j++)
        {
            output[i*16+j] = outputBlock[j];
        }
    }
    return output;
}

/**
* Removes the padding from a message
*
* @param message is the padded message
* @param len is the length of the padded message
* @return the original message without padding
*/
byte *Aes::removePadding(byte* message, int len)
{
    // add checks for invalid padding of message???
    int index = paddingStartIndex(message, len);
    byte* messageWithoutPadding = new byte[index];
    for(int i=0;i<index;i++)
    {
        messageWithoutPadding[i] = message[i];
    }
    return messageWithoutPadding;
}

/**
* Finds the index where the padding starts on the message
*
* @param message is the padded message
* @param len is the length of padded message
* @return the index where the padding starts
*/
int Aes::paddingStartIndex(byte* message, int len)
{
    int index = -1;
    for(int i=len-1;i>=0;i--)
    {
        if(message[i] == 0x01)
        {
            index = i;
            break;
        }
    }
    return index;
}

/**
*  Decrypt a message using ECB mode
*
* @param cipher is the message to be decrypted
* @param cipherLen is the length of the cipher text
* @param key is the randomly generated key
* @return the decrypted message
*/
byte *Aes::decryptECB(byte* cipher, int cipherLen, byte* key)
{
    byte* message = new byte[cipherLen];

    byte** w = new byte*[4]; //allocate memory for rows  (4 bytes)
    for(int i = 0; i < 4; i++) //allocate columns, the number of key expasions
    {
        w[i] = new byte[Nb * (Nr+1)]; //key schedule for 128 its 44
    }

    w = KeyExpansion(key, w);

    for(int i=0;i<cipherLen/16;i++)
    {
        byte* currentBlock = new byte[16];
        byte* messageBlock = new byte[16];
        for(int j=0;j<16;j++)
        {
            currentBlock[j] = cipher[i*16+j];
        }
        messageBlock = InvCipher(currentBlock, w);

        for(int j=0; j<16;j++)
        {
            message[i*16+j] = messageBlock[j];
        }
    }
    return removePadding(message, cipherLen);
}

/**
* Encrypt a message using CBC mode
*
* @param input is the message to be encrypted
* @param messageLen is the length of the message
* @param key is the randomly generated key
* @param IV is the initialization vector
* @return the encrypted message
*/
byte *Aes::encryptCBC(byte *input, int messageLen, byte *key, byte *IV)
{
    byte *paddedMessage = getPaddedMessage(input, messageLen);
    int paddedMessageLen = messageLen + 16 - messageLen % 16;
    byte *output = new byte[paddedMessageLen];

    byte **w = new byte *[4];   //allocate memory for rows  (4 bytes)
    for (int i = 0; i < 4; i++) //allocate columns, the number of key expasions
    {
        w[i] = new byte[Nb * (Nr + 1)]; //key schedule for 128 its 44
    }

    w = KeyExpansion(key, w);

    byte *previousCipherBlock = new byte[16];

    for (int i = 0; i < paddedMessageLen / 16; i++)
    {
        byte *currentBlock = new byte[16];
        byte *currentInput = new byte[16];
        byte *outputBlock = new byte[16];
        for (int j = 0; j < 16; j++)
        {
            currentBlock[j] = paddedMessage[i * 16 + j];
        }

        if(i==0)
        {
            for(int j=0;j<16;j++)
            {
                currentInput[j] = currentBlock[j] ^ IV[j];
            }
        }
        else
        {
            for (int j = 0; j < 16; j++)
            {
                currentInput[j] = currentBlock[j] ^ previousCipherBlock[j];
            }
        }


        outputBlock = Cipher(currentInput, w);
        previousCipherBlock = outputBlock;
        for (int j = 0; j < 16; j++)
        {
            output[i * 16 + j] = outputBlock[j];
        }
    }
    return output;
}

/**
* Decrypt a message using CBC mode
*
* @param cipher is the message to be decrypted
* @param messageLen is the length of the cipher text
* @param key is the randomly generated key
* @param IV is the initialization vector
* @return the decrypted message
*/
byte *Aes::decryptCBC(byte *cipher, int cipherLen, byte *key, byte *IV)
{
    byte *message = new byte[cipherLen];

    byte **w = new byte *[4];   //allocate memory for rows  (4 bytes)
    for (int i = 0; i < 4; i++) //allocate columns, the number of key expasions
    {
        w[i] = new byte[Nb * (Nr + 1)]; //key schedule for 128 its 44
    }

    w = KeyExpansion(key, w);

    byte *previousCipherBlock = new byte[16];

    for (int i = 0; i < cipherLen / 16; i++)
    {
        byte *currentBlock = new byte[16];
        byte *messageBlock = new byte[16];
        byte *decryptBlock = new byte[16];
        for (int j = 0; j < 16; j++)
        {
            currentBlock[j] = cipher[i * 16 + j];
        }
        decryptBlock = InvCipher(currentBlock, w);


        if(i==0)
        {
            for(int j=0;j<16;j++)
            {
                messageBlock[j] = decryptBlock[j] ^IV[j];
            }
        }
        else
        {
            for (int j = 0; j < 16; j++)
            {
                messageBlock[j] = decryptBlock[j] ^ previousCipherBlock[j];
            }
        }

        for (int j = 0; j < 16; j++)
        {
            message[i * 16 + j] = messageBlock[j];
        }
        previousCipherBlock = currentBlock;
    }
    // return removePadding(message, cipherLen); // resulting in a memmory allocation error,
    // memory going out of bounds while creating a new messagewithoutpadding in removepadding
    return message;
}

byte *Aes::encryptOFB(byte *input, int messageLen, byte *key, byte *IV)
{
    byte *cipher = new byte[messageLen];

    byte **w = new byte *[4];   //allocate memory for rows  (4 bytes)
    for (int i = 0; i < 4; i++) //allocate columns, the number of key expasions
    {
        w[i] = new byte[Nb * (Nr + 1)]; //key schedule for 128 its 44
    }

    w = KeyExpansion(key, w);

    byte *previousOutputBlock = new byte[16];

    double limit = (double)messageLen / 16;

    for (double i = 0; i < limit; i++)
    {
        byte *currentBlock = new byte[16];
        byte *currentInput = new byte[16];
        byte *outputBlock = new byte[16];
        byte *cipherBlock = new byte[16];

        if(!(i==floor(messageLen/16)))
        {
            for (int j = 0; j < 16; j++)
            {
                currentBlock[j] = input[(int)i * 16 + j];
            }
        }
        else
        {
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                currentBlock[j] = input[(int)i * 16 + j];
            }
        }

        if((int)i==0)
        {
            for(int j=0;j<16;j++)
            {
                currentInput[j] = IV[j];
            }
        }
        else
        {
            for (int j = 0; j < 16; j++)
            {
                currentInput[j] = previousOutputBlock[j];
            }
        }
        // cout<<"P:\t"<<blockToReadable(currentBlock)<<"\n";
        // cout<<"I:\t"<<blockToReadable(currentInput)<<"\n";

        outputBlock = Cipher(currentInput, w);
        previousOutputBlock = outputBlock;
        // cout<<"O:\t"<<blockToReadable(outputBlock)<<"\n";

        if(!(i==floor(messageLen/16)))
        {
            for (int j = 0; j < 16; j++)
            {
                cipherBlock[j] = currentBlock[j] ^ outputBlock[j];
            }
            for (int j = 0; j < 16; j++)
            {
                cipher[(int)i * 16 + j] = cipherBlock[j];
            }
        }
        else
        {
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                cipherBlock[j] = currentBlock[j] ^ outputBlock[j];
            }
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                cipher[(int)i * 16 + j] = cipherBlock[j];
            }
        }
        // cout<<"C:\t"<<blockToReadable(cipherBlock)<<"\n\n";
    }
    return cipher;
}

byte *Aes::decryptOFB(byte *input, int messageLen, byte *key, byte *IV)
{
    // don't be misled by variable names, this is actually the decrypt function
    // Its just most of it was copy pasta
    byte *cipher = new byte[messageLen];

    byte **w = new byte *[4];   //allocate memory for rows  (4 bytes)
    for (int i = 0; i < 4; i++) //allocate columns, the number of key expasions
    {
        w[i] = new byte[Nb * (Nr + 1)]; //key schedule for 128 its 44
    }

    w = KeyExpansion(key, w);

    byte *previousOutputBlock = new byte[16];

    double limit = (double)messageLen / 16;

    for (double i = 0; i < limit; i++)
    {
        byte *currentBlock = new byte[16];
        byte *currentInput = new byte[16];
        byte *outputBlock = new byte[16];
        byte *cipherBlock = new byte[16];

        if(!(i==floor(messageLen/16)))
        {
            for (int j = 0; j < 16; j++)
            {
                currentBlock[j] = input[(int)i * 16 + j];
            }
        }
        else
        {
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                currentBlock[j] = input[(int)i * 16 + j];
            }
        }

        if((int)i==0)
        {
            for(int j=0;j<16;j++)
            {
                currentInput[j] = IV[j];
            }
        }
        else
        {
            for (int j = 0; j < 16; j++)
            {
                currentInput[j] = previousOutputBlock[j];
            }
        }
        // cout<<"P:\t"<<blockToReadable(currentBlock)<<"\n";
        // cout<<"I:\t"<<blockToReadable(currentInput)<<"\n";

        outputBlock = Cipher(currentInput, w);
        previousOutputBlock = outputBlock;
        // cout<<"O:\t"<<blockToReadable(outputBlock)<<"\n";

        if(!(i==floor(messageLen/16)))
        {
            for (int j = 0; j < 16; j++)
            {
                cipherBlock[j] = currentBlock[j] ^ outputBlock[j];
            }
            for (int j = 0; j < 16; j++)
            {
                cipher[(int)i * 16 + j] = cipherBlock[j];
            }
        }
        else
        {
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                cipherBlock[j] = currentBlock[j] ^ outputBlock[j];
            }
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                cipher[(int)i * 16 + j] = cipherBlock[j];
            }
        }
        // cout<<"C:\t"<<blockToReadable(cipherBlock)<<"\n\n";
    }
    return cipher;
}

byte *Aes::incrementCTR(byte *IV)
{
    byte one = 0x01;
    byte zero = 0x00;
    byte full = 0xff;
    byte* incIV = new byte[16];
    for(int i=0;i<16;i++)
    {
        incIV[i]=IV[i];
    }
    // cout<<"incIV "<<blockToReadable(incIV)<<"\n";
    if(!((int)IV[15]==(int)0xff))
    {
        incIV[15] = incIV[15] + one;
        return incIV;
    }
    else
    {
        // for(int i=15;i>=0;i--)
        // {
            incIV[15] = zero;
            int index = -1;
            for(int j=14;j>=0;j--)
            {
                // cout<<"IV[j] "<<(int)IV[j]<<" full "<<(int)full<<"\n";
                if(!((int)IV[j]==(int)full))
                {

                    index = j;
                    break;
                }
            }
            // cout<<"index "<<index<<"\n";
            for(int j=14;j>index;j--)
            {
                incIV[j] = zero;
            }
            incIV[index] = incIV[index]+one;
        // }
        // cout<<"returning after incrementing "<<blockToReadable(incIV)<<"\n";
        return incIV;
    }
}

byte *Aes::encryptCTR(byte *input, int messageLen, byte *key, byte *IV)
{
    byte *cipher = new byte[messageLen];

    byte **w = new byte *[4];   //allocate memory for rows  (4 bytes)
    for (int i = 0; i < 4; i++) //allocate columns, the number of key expasions
    {
        w[i] = new byte[Nb * (Nr + 1)]; //key schedule for 128 its 44
    }

    w = KeyExpansion(key, w);

    byte *previousInputBlock = new byte[16];

    double limit = (double)messageLen / 16;

    for (double i = 0; i < limit; i++)
    {
        byte *currentBlock = new byte[16];
        byte *currentInput = new byte[16];
        byte *outputBlock = new byte[16];
        byte *cipherBlock = new byte[16];

        if(!(i==floor(messageLen/16)))
        {
            for (int j = 0; j < 16; j++)
            {
                currentBlock[j] = input[(int)i * 16 + j];
            }
        }
        else
        {
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                currentBlock[j] = input[(int)i * 16 + j];
            }
        }

        if((int)i==0)
        {
            for(int j=0;j<16;j++)
            {
                currentInput[j] = IV[j];
            }
        }
        else
        {
            // for (int j = 0; j < 16; j++)
            // {
                currentInput = incrementCTR(previousInputBlock);
            // }
        }
        // cout<<"P:\t"<<blockToReadable(currentBlock)<<"\n";
        // cout<<"I:\t"<<blockToReadable(currentInput)<<"\n";

        outputBlock = Cipher(currentInput, w);
        previousInputBlock = currentInput;
        // cout<<"O:\t"<<blockToReadable(outputBlock)<<"\n";

        if(!(i==floor(messageLen/16)))
        {
            for (int j = 0; j < 16; j++)
            {
                cipherBlock[j] = currentBlock[j] ^ outputBlock[j];
            }
            for (int j = 0; j < 16; j++)
            {
                cipher[(int)i * 16 + j] = cipherBlock[j];
            }
        }
        else
        {
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                cipherBlock[j] = currentBlock[j] ^ outputBlock[j];
            }
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                cipher[(int)i * 16 + j] = cipherBlock[j];
            }
        }
        // cout<<"C:\t"<<blockToReadable(cipherBlock)<<"\n\n";
    }
    return cipher;
}

byte *Aes::decryptCTR(byte *input, int messageLen, byte *key, byte *IV)
{
    byte *cipher = new byte[messageLen];

    byte **w = new byte *[4];   //allocate memory for rows  (4 bytes)
    for (int i = 0; i < 4; i++) //allocate columns, the number of key expasions
    {
        w[i] = new byte[Nb * (Nr + 1)]; //key schedule for 128 its 44
    }

    w = KeyExpansion(key, w);

    byte *previousInputBlock = new byte[16];

    double limit = (double)messageLen / 16;

    for (double i = 0; i < limit; i++)
    {
        byte *currentBlock = new byte[16];
        byte *currentInput = new byte[16];
        byte *outputBlock = new byte[16];
        byte *cipherBlock = new byte[16];

        if(!(i==floor(messageLen/16)))
        {
            for (int j = 0; j < 16; j++)
            {
                currentBlock[j] = input[(int)i * 16 + j];
            }
        }
        else
        {
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                currentBlock[j] = input[(int)i * 16 + j];
            }
        }

        if((int)i==0)
        {
            for(int j=0;j<16;j++)
            {
                currentInput[j] = IV[j];
            }
        }
        else
        {
            // for (int j = 0; j < 16; j++)
            // {
                currentInput = incrementCTR(previousInputBlock);
            // }
        }
        // cout<<"P:\t"<<blockToReadable(currentBlock)<<"\n";
        // cout<<"I:\t"<<blockToReadable(currentInput)<<"\n";

        outputBlock = Cipher(currentInput, w);
        previousInputBlock = currentInput;
        // cout<<"O:\t"<<blockToReadable(outputBlock)<<"\n";

        if(!(i==floor(messageLen/16)))
        {
            for (int j = 0; j < 16; j++)
            {
                cipherBlock[j] = currentBlock[j] ^ outputBlock[j];
            }
            for (int j = 0; j < 16; j++)
            {
                cipher[(int)i * 16 + j] = cipherBlock[j];
            }
        }
        else
        {
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                cipherBlock[j] = currentBlock[j] ^ outputBlock[j];
            }
            for (int j = 0; j < messageLen-(int)i*16; j++)
            {
                cipher[(int)i * 16 + j] = cipherBlock[j];
            }
        }
        // cout<<"C:\t"<<blockToReadable(cipherBlock)<<"\n\n";
    }
    return cipher;
}

// int main()
// {
//  Aes aes(128);
//  byte message[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
//              0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e ,0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
//              0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
//              0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

//  byte cipherKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
//  byte IV[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
//  string expectedCipher = "76 49 ab ac 81 19 b2 46 ce e9 8e 9b 12 e9 19 7d "
//              "50 86 cb 9b 50 72 19 ee 95 db 11 3a 91 76 78 b2 "
//              "73 be d6 b8 e3 c1 74 3b 71 16 e6 9e 22 22 95 16 "
//              "3f f1 ca a1 68 1f ac 9 12 e ca 30 75 86 e1 a7 "
//              "7e 31 3b 5d 59 58 52 8d bb 41 56 13 d 93 af 3c";//because of padding
//  byte *output = aes.encryptCBC(message, 64, cipherKey, IV);
//  cout << aes.blockToReadable(output, 80);
//  // ASSERT_EQ(expectedCipher, aes.blockToReadable(output, 80));

//  byte *input = aes.decryptCBC(output, 80, cipherKey, IV);
//  cout << aes.blockToReadable(input, 64);
//  string expectedMessage = "6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a "
//                           "ae 2d 8a 57 1e 3 ac 9c 9e b7 6f ac 45 af 8e 51 "
//                           "30 c8 1c 46 a3 5c e4 11 e5 fb c1 19 1a a 52 ef"
//                           "f6 9f 24 45 df 4f 9b 17 ad 2b 41 7b e6 6c 37 10";
//  // ASSERT_EQ(expectedMessage, aes.blockToReadable(input, 64));
//  return 0;
// }
