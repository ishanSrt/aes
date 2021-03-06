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

TEST(TestECB, DecryptTest1)
{
    Aes aes(128);
    byte cipherKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte Cipher[32] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
                       0x7e, 0x59, 0x37, 0x9b, 0x52, 0x33, 0x96, 0x9d, 0x25, 0xa5, 0xad, 0x2c, 0xe3, 0x35, 0xcb, 0x3e};
    string expectedCipher = "32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 7 34";
    byte* output = aes.decryptECB(Cipher, 32, cipherKey);
    ASSERT_EQ(expectedCipher, aes.blockToReadable(output));
}

TEST(TestCBC, Test1)
{
    Aes aes(128);
    byte message[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e ,0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    byte cipherKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte IV[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    string expectedCipher = "76 49 ab ac 81 19 b2 46 ce e9 8e 9b 12 e9 19 7d "
                "50 86 cb 9b 50 72 19 ee 95 db 11 3a 91 76 78 b2 "
                "73 be d6 b8 e3 c1 74 3b 71 16 e6 9e 22 22 95 16 "
                "3f f1 ca a1 68 1f ac 9 12 e ca 30 75 86 e1 a7 "
                "7e 31 3b 5d 59 58 52 8d bb 41 56 13 d 93 af 3c";//because of padding
    byte *output = aes.encryptCBC(message, 64, cipherKey, IV);
    // cout << aes.blockToReadable(output, 80);
    ASSERT_EQ(expectedCipher, aes.blockToReadable(output, 80));

    byte *input = aes.decryptCBC(output, 80, cipherKey, IV);
    // cout << aes.blockToReadable(input, 64);
    string expectedMessage = "6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a "
                             "ae 2d 8a 57 1e 3 ac 9c 9e b7 6f ac 45 af 8e 51 "
                             "30 c8 1c 46 a3 5c e4 11 e5 fb c1 19 1a a 52 ef "
                             "f6 9f 24 45 df 4f 9b 17 ad 2b 41 7b e6 6c 37 10";
    ASSERT_EQ(expectedMessage, aes.blockToReadable(input, 64));

}

TEST(TestOFB, Test1)
{
    Aes aes(128);

    byte message[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};

    byte cipherKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte IV[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    string expectedCipher = "3b 3f d9 2e b7 2d ad 20 33 34 49 f8 e8 3c fb 4a "
                            "77 89 50 8d 16 91 8f 3 f5 3c 52 da c5 4e d8 25 "
                            "97 40 5 1e 9c 5f ec f6 43 44 f7 a8 22 60 ed cc "
                            "30 4c 65 28 f6 59 c7 78 66 a5 10 d9 c1 d6 ae 5e";
    byte *output = aes.encryptOFB(message, 64, cipherKey, IV);
    // cout << aes.blockToReadable(output, 64);
    ASSERT_EQ(expectedCipher, aes.blockToReadable(output, 64));

    byte *input = aes.decryptOFB(output, 64, cipherKey, IV);
    // cout << aes.blockToReadable(input, 64);
    string expectedMessage = "6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a "
                             "ae 2d 8a 57 1e 3 ac 9c 9e b7 6f ac 45 af 8e 51 "
                             "30 c8 1c 46 a3 5c e4 11 e5 fb c1 19 1a a 52 ef "
                             "f6 9f 24 45 df 4f 9b 17 ad 2b 41 7b e6 6c 37 10";
    ASSERT_EQ(expectedMessage, aes.blockToReadable(input, 64));

}

TEST(TestOFB, TestMessagenotmultipleofblocksize)
{
    Aes aes(128);

    byte message[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37};

    byte cipherKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte IV[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    string expectedCipher = "3b 3f d9 2e b7 2d ad 20 33 34 49 f8 e8 3c fb 4a "
                            "77 89 50 8d 16 91 8f 3 f5 3c 52 da c5 4e d8 25 "
                            "97 40 5 1e 9c 5f ec f6 43 44 f7 a8 22 60 ed cc "
                            "30 4c 65 28 f6 59 c7 78 66 a5 10 d9 c1 d6 ae";
    byte *output = aes.encryptOFB(message, 63, cipherKey, IV);
    // cout << aes.blockToReadable(output, 63);
    ASSERT_EQ(expectedCipher, aes.blockToReadable(output, 63));

    byte *input = aes.decryptOFB(output, 63, cipherKey, IV);
    // cout << aes.blockToReadable(input, 64);
    string expectedMessage = "6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a "
                             "ae 2d 8a 57 1e 3 ac 9c 9e b7 6f ac 45 af 8e 51 "
                             "30 c8 1c 46 a3 5c e4 11 e5 fb c1 19 1a a 52 ef "
                             "f6 9f 24 45 df 4f 9b 17 ad 2b 41 7b e6 6c 37";
    ASSERT_EQ(expectedMessage, aes.blockToReadable(input, 63));

}

TEST(TestCTR, Test1)
{
    Aes aes(128);
    byte cipherKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    byte message[64] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                       0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                       0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                       0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    byte IV[16] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    byte *output = aes.encryptCTR(message, 64, cipherKey, IV);
    // cout << aes.blockToReadable(output, 64);
    string expectedCipher = "87 4d 61 91 b6 20 e3 26 1b ef 68 64 99 d b6 ce "
                            "98 6 f6 6b 79 70 fd ff 86 17 18 7b b9 ff fd ff "
                            "5a e4 df 3e db d5 d3 5e 5b 4f 9 2 d b0 3e ab "
                            "1e 3 1d da 2f be 3 d1 79 21 70 a0 f3 0 9c ee";
    ASSERT_EQ(expectedCipher, aes.blockToReadable(output, 64));

    byte *input = aes.decryptCTR(output, 64, cipherKey, IV);
    string expectedMessage = "6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 "
                             "2a ae 2d 8a 57 1e 3 ac 9c 9e b7 6f ac 45 af "
                             "8e 51 30 c8 1c 46 a3 5c e4 11 e5 fb c1 19 "
                             "1a a 52 ef f6 9f 24 45 df 4f 9b 17 ad 2b 41 7b e6 6c 37 10";
    ASSERT_EQ(expectedMessage, aes.blockToReadable(input, 64));
}

int main(int argc, char **argv)
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
