#include "aes.cpp"

int main()
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
    cout << "cipher:\n"<< aes.blockToReadable(output, 80)<<"\n\n";
    // ASSERT_EQ(expectedCipher, aes.blockToReadable(output, 80));

    byte *input = aes.decryptCBC(output, 80, cipherKey, IV);
    cout << "message:\n"<<aes.blockToReadable(input, 64);
    string expectedMessage = "6b c1 be e2 2e 40 9f 96 e9 3d 7e 11 73 93 17 2a "
                             "ae 2d 8a 57 1e 3 ac 9c 9e b7 6f ac 45 af 8e 51 "
                             "30 c8 1c 46 a3 5c e4 11 e5 fb c1 19 1a a 52 ef"
                             "f6 9f 24 45 df 4f 9b 17 ad 2b 41 7b e6 6c 37 10";
    // ASSERT_EQ(expectedMessage, aes.blockToReadable(input, 64));
    return 0;
}