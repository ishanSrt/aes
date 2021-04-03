#include <iostream>
#include <gtest/gtest.h>
#include "../src/aes.cpp"

using namespace std;

TEST(StdTestCase1, KeyLen128)
{
	byte message[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	byte cipherKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	Aes aes(128);
	byte* output;

	byte** w = new byte*[4]; //allocate memory for rows  (4 bytes)
	for(int i = 0; i < 4; i++) //allocate columns, the number of key expasions
	{
		w[i] = new byte[aes.getNb() * (aes.getNr()+1)]; //key schedule for 128 its 44
	}
	
	w = aes.KeyExpansion(cipherKey, w);

	output = aes.Cipher(message, w);
	string expected = "39 25 84 1d 2 dc 9 fb dc 11 85 97 19 6a b 32";
	ASSERT_EQ(expected,aes.blockToReadable(output));

	output = aes.InvCipher(output, w);  //decrypt the message
	expected = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 7 34";
	ASSERT_EQ(expected,aes.blockToReadable(output));
}

TEST(StdTestCase1, KeyLen192)
{
	Aes aes(192);
	byte message[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	byte cipherKey[aes.getNk()*aes.getNb()] = {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b};
	
	byte* output;

	byte** w = new byte*[4]; //allocate memory for rows  (4 bytes)
	for(int i = 0; i < 4; i++) //allocate columns, the number of key expasions
	{
		w[i] = new byte[aes.getNb() * (aes.getNr()+1)]; //key schedule for 128 its 44
	}
	
	w = aes.KeyExpansion(cipherKey, w);

	output = aes.Cipher(message, w);
	string expectedCipher = "58 5e 9f b6 c2 72 2b 9a f4 f4 92 c1 2b b0 24 c1";
	ASSERT_EQ(expectedCipher,aes.blockToReadable(output));

	output = aes.InvCipher(output, w);  //decrypt the message
	string expectedMessage = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 7 34";
	ASSERT_EQ(expectedMessage,aes.blockToReadable(output));
}

TEST(StdTestCase1, KeyLen256)
{
	Aes aes(256);
	byte message[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	byte cipherKey[aes.getNk()*aes.getNb()] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
	
	byte* output;

	byte** w = new byte*[4]; //allocate memory for rows  (4 bytes)
	for(int i = 0; i < 4; i++) //allocate columns, the number of key expasions
	{
		w[i] = new byte[aes.getNb() * (aes.getNr()+1)]; //key schedule for 128 its 44
	}
	
	w = aes.KeyExpansion(cipherKey, w);

	output = aes.Cipher(message, w);
	string expectedCipher = "30 21 61 3a 97 3e 58 2f 4a 29 23 41 37 ae c4 94";
	ASSERT_EQ(expectedCipher,aes.blockToReadable(output));

	output = aes.InvCipher(output, w);  //decrypt the message
	string expectedMessage = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 7 34";
	ASSERT_EQ(expectedMessage,aes.blockToReadable(output));
}

//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// WRONG TEST CASE USING 256 bit key but aes algorithm working for 128 bit key
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
TEST(WrongTestCaseStdTestCase1AesWorkingWith128, KeyLen256)
{
	Aes aes(128);
	byte message[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	byte cipherKey[aes.getNk()*aes.getNb()] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
	
	byte* output;

	byte** w = new byte*[4]; //allocate memory for rows  (4 bytes)
	for(int i = 0; i < 4; i++) //allocate columns, the number of key expasions
	{
		w[i] = new byte[aes.getNb() * (aes.getNr()+1)]; //key schedule for 128 its 44
	}
	
	w = aes.KeyExpansion(cipherKey, w);

	output = aes.Cipher(message, w);
	string expectedCipher = "6 4a 49 df 5a db e5 9a 23 d2 9a a3 15 b4 e5 3d";
	ASSERT_EQ(expectedCipher,aes.blockToReadable(output));

	output = aes.InvCipher(output, w);  //decrypt the message
	string expectedMessage = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 7 34";
	ASSERT_EQ(expectedMessage,aes.blockToReadable(output));
}
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// WRONG TEST CASE USING 256 bit key but aes algorithm working for 128 bit key ^^^^
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


TEST(StdTestCase2, KeyLen128)
{
	Aes aes(128);
	byte message[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	byte cipherKey[aes.getNk()*aes.getNb()] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	
	byte* output;

	byte** w = new byte*[4]; //allocate memory for rows  (4 bytes)
	for(int i = 0; i < 4; i++) //allocate columns, the number of key expasions
	{
		w[i] = new byte[aes.getNb() * (aes.getNr()+1)]; //key schedule for 128 its 44
	}
	
	w = aes.KeyExpansion(cipherKey, w);

	output = aes.Cipher(message, w);
	string expectedCipher = "69 c4 e0 d8 6a 7b 4 30 d8 cd b7 80 70 b4 c5 5a";
	ASSERT_EQ(expectedCipher,aes.blockToReadable(output));

	output = aes.InvCipher(output, w);  //decrypt the message
	string expectedMessage = "0 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff";
	ASSERT_EQ(expectedMessage,aes.blockToReadable(output));
}

TEST(StdTestCase2, KeyLen192)
{
	Aes aes(192);
	byte message[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	byte cipherKey[aes.getNk()*aes.getNb()] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
	
	byte* output;

	byte** w = new byte*[4]; //allocate memory for rows  (4 bytes)
	for(int i = 0; i < 4; i++) //allocate columns, the number of key expasions
	{
		w[i] = new byte[aes.getNb() * (aes.getNr()+1)]; //key schedule for 128 its 44
	}
	
	w = aes.KeyExpansion(cipherKey, w);

	output = aes.Cipher(message, w);
	string expectedCipher = "dd a9 7c a4 86 4c df e0 6e af 70 a0 ec d 71 91";
	ASSERT_EQ(expectedCipher,aes.blockToReadable(output));

	output = aes.InvCipher(output, w);  //decrypt the message
	string expectedMessage = "0 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff";
	ASSERT_EQ(expectedMessage,aes.blockToReadable(output));
}

TEST(StdTestCase2, KeyLen256)
{
	Aes aes(256);
	byte message[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	byte cipherKey[aes.getNk()*aes.getNb()] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
											   0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
											   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
	
	byte* output;

	byte** w = new byte*[4]; //allocate memory for rows  (4 bytes)
	for(int i = 0; i < 4; i++) //allocate columns, the number of key expasions
	{
		w[i] = new byte[aes.getNb() * (aes.getNr()+1)]; //key schedule for 128 its 44
	}
	
	w = aes.KeyExpansion(cipherKey, w);

	output = aes.Cipher(message, w);
	string expectedCipher = "8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89";
	ASSERT_EQ(expectedCipher,aes.blockToReadable(output));

	output = aes.InvCipher(output, w);  //decrypt the message
	string expectedMessage = "0 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff";
	ASSERT_EQ(expectedMessage,aes.blockToReadable(output));
}

TEST(TestECB, EncryptTest1)
{
	Aes aes(128);
	byte message[32] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
						0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	byte cipherKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
	string expectedCipher = "39 25 84 1d 2 dc 9 fb dc 11 85 97 19 6a b 32 7e 59 37 9b 52 33 96 9d 25 a5 ad 2c e3 35 cb 3e 7e 59 37 9b 52 33 96 9d 25 a5 ad 2c e3 35 cb 3e";
	byte* output = aes.encryptECB(message, 32, cipherKey);
	ASSERT_EQ(expectedCipher, aes.blockToReadable(output, 48));
}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
