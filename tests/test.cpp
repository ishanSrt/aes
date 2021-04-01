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
	ASSERT_EQ(expected,blockToReadable(output));

	output = aes.InvCipher(output, w);  //decrypt the message
	expected = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 7 34";
	ASSERT_EQ(expected,blockToReadable(output));
}

int main(int argc, char **argv)
{
	testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
