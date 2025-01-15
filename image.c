#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// AES S-Box
static const uint8_t SBox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,  // 0
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,  // 1
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,  // 2
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,  // 3
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,  // 4
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,  // 5
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,  // 6
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,  // 7
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,  // 9
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,  // A
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,  // B
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,  // C
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,  // D
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,  // E
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16   // F
    /* Add the full SBox here... */
};

// AES Inverse S-Box
static const uint8_t InvSBox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, //0
     0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, //1
     0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, //2
     0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, //3
     0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, //4
     0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, //5
     0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, //6
     0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, //7
     0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, //8
     0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, //9
     0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, //A
     0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, //B
     0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, //C
     0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, //D
     0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, //E
     0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  //F
    /* Add the full InvSBox here... */
};

// Rcon array for KeyExpansion
static const uint8_t Rcon[11] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x00};

// Function to substitute bytes using SBox
void SubBytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = SBox[state[i]];
    }
}

// Function to substitute bytes using InvSBox
void InvSubBytes(uint8_t *state) {
    for (int i = 0; i < 16; i++) {
        state[i] = InvSBox[state[i]];
    }
}

static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        uint8_t hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1b; // XOR with AES polynomial
        }
        b >>= 1;
    }
    return p;
}

void MixColumns(uint8_t *state) {
    uint8_t temp[16];
    for (int i = 0; i < 4; i++) {
        uint8_t *col = &state[i * 4];
        temp[i * 4 + 0] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2] ^ col[3];
        temp[i * 4 + 1] = col[0] ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3];
        temp[i * 4 + 2] = col[0] ^ col[1] ^ gmul(col[2], 2) ^ gmul(col[3], 3);
        temp[i * 4 + 3] = gmul(col[0], 3) ^ col[1] ^ col[2] ^ gmul(col[3], 2);
    }
    memcpy(state, temp, 16);
}

// Function to perform InvMixColumns
void InvMixColumns(uint8_t *state) {
    uint8_t temp[16];
    for (int i = 0; i < 4; i++) {
        uint8_t *col = &state[i * 4];
        temp[i * 4 + 0] = gmul(col[0], 0x0e) ^ gmul(col[1], 0x0b) ^ gmul(col[2], 0x0d) ^ gmul(col[3], 0x09);
        temp[i * 4 + 1] = gmul(col[0], 0x09) ^ gmul(col[1], 0x0e) ^ gmul(col[2], 0x0b) ^ gmul(col[3], 0x0d);
        temp[i * 4 + 2] = gmul(col[0], 0x0d) ^ gmul(col[1], 0x09) ^ gmul(col[2], 0x0e) ^ gmul(col[3], 0x0b);
        temp[i * 4 + 3] = gmul(col[0], 0x0b) ^ gmul(col[1], 0x0d) ^ gmul(col[2], 0x09) ^ gmul(col[3], 0x0e);
    }
    memcpy(state, temp, 16);
}

// Function to perform ShiftRows operation
void ShiftRows(uint8_t *state) {
    uint8_t temp[16];

    temp[0] = state[0];
    temp[1] = state[5];
    temp[2] = state[10];
    temp[3] = state[15];

    temp[4] = state[4];
    temp[5] = state[9];
    temp[6] = state[14];
    temp[7] = state[3];

    temp[8] = state[8];
    temp[9] = state[13];
    temp[10] = state[2];
    temp[11] = state[7];

    temp[12] = state[12];
    temp[13] = state[1];
    temp[14] = state[6];
    temp[15] = state[11];

    memcpy(state, temp, 16);
}

// Function to perform inverse ShiftRows
void InvShiftRows(uint8_t *state) {
    uint8_t temp[16];

    temp[0] = state[0];
    temp[1] = state[13];
    temp[2] = state[10];
    temp[3] = state[7];

    temp[4] = state[4];
    temp[5] = state[1];
    temp[6] = state[14];
    temp[7] = state[11];

    temp[8] = state[8];
    temp[9] = state[5];
    temp[10] = state[2];
    temp[11] = state[15];

    temp[12] = state[12];
    temp[13] = state[9];
    temp[14] = state[6];
    temp[15] = state[3];

    memcpy(state, temp, 16);
}

// Function to XOR state with round key
void AddRoundKey(uint8_t *state, uint8_t *roundKey) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

// Function to perform KeyExpansion
void KeyExpansion(const uint8_t *key, uint8_t *roundKeys) {
    uint32_t i, j;
    uint8_t temp[4];

    for (i = 0; i < 16; i++) {
        roundKeys[i] = key[i];
    }

    for (i = 16; i < 176; i += 4) {
        for (j = 0; j < 4; j++) {
            temp[j] = roundKeys[i - 4 + j];
        }

        if (i % 16 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            for (j = 0; j < 4; j++) {
                temp[j] = SBox[temp[j]];
            }
            temp[0] ^= Rcon[i / 16 - 1];
        }

        for (j = 0; j < 4; j++) {
            roundKeys[i + j] = roundKeys[i - 16 + j] ^ temp[j];
        }
    }
}

// AES encryption function
void AES_encrypt(uint8_t *input, uint8_t *output, uint8_t *key) {
    uint8_t state[16];
    uint8_t roundKeys[176];

    memcpy(state, input, 16);
    KeyExpansion(key, roundKeys);

    AddRoundKey(state, roundKeys);

    for (int round = 1; round <= 9; round++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }

    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 160);

    memcpy(output, state, 16);
}

// AES decryption function
void AES_decrypt(uint8_t *input, uint8_t *output, uint8_t *key) {
    uint8_t state[16];
    uint8_t roundKeys[176];

    memcpy(state, input, 16);
    KeyExpansion(key, roundKeys);

    AddRoundKey(state, roundKeys + 160);

    for (int round = 9; round >= 1; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round * 16);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    memcpy(output, state, 16);
}

// Function to read and write pixel data from a simple image format
void encryptImageData(const char *inputFile, const char *outputFile, uint8_t *key) {
    FILE *in = fopen(inputFile, "rb");
    

    FILE *out = fopen(outputFile, "wb");
    

    // Read and write the header (assuming first 54 bytes for BMP, adjust for other formats)
    uint8_t header[54];
    fread(header, 1, 54, in); // For BMP; adjust for PNG/JPG headers
    fwrite(header, 1, 54, out);

    // Encrypt the pixel data
    uint8_t buffer[16];
    uint8_t ciphertext[16];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, 16, in)) > 0) {
        if (bytesRead < 16) {
            // Add padding if necessary
            for (size_t i = bytesRead; i < 16; i++) {
                buffer[i] = 16 - bytesRead;
            }
        }
        AES_encrypt(buffer, ciphertext, key);
        fwrite(ciphertext, 1, 16, out);
    }

    fclose(in);
    fclose(out);
}

void decryptImageData(const char *inputFile, const char *outputFile, uint8_t *key) {
    FILE *in = fopen(inputFile, "rb");
    

    FILE *out = fopen(outputFile, "wb");
    

    // Read and write the header
    uint8_t header[54];
    fread(header, 1, 54, in); // For BMP
    fwrite(header, 1, 54, out);

    // Decrypt the pixel data
    uint8_t buffer[16];
    uint8_t plaintext[16];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, 16, in)) > 0) {
        AES_decrypt(buffer, plaintext, key);
        if (bytesRead < 16) {
            // Remove padding
            uint8_t padding = plaintext[bytesRead - 1];
            bytesRead -= padding;
        }
        fwrite(plaintext, 1, bytesRead, out);
    }

    fclose(in);
    fclose(out);
}

int main() {
    uint8_t key[16] = "ThisIsAKey123...";
    const char *inputImage = "Aimage.bmp";  
    const char *encryptedImage = "encrypted_image.bmp";
    const char *decryptedImage = "decrypted_image.bmp";

    printf("Encrypting the image...\n");
    encryptImageData(inputImage, encryptedImage, key);

    printf("Decrypting the image...\n");
    decryptImageData(encryptedImage, decryptedImage, key);

    printf("Done! Check the files.\n");
    return 0;
}