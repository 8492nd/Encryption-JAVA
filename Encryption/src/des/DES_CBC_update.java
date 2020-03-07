package des;

import java.util.Arrays;

public class DES_CBC_update {
	// High-level permutations

    private static final byte[] IP = { 
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
    };

    private static final byte[] FP = {
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25
    };

    // Permutations relating to the Feistel function.

    private static final byte[] E = {
        32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    };

    private static final byte[][] S = { {
        14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
        0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8,
        4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
        15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13
    }, {
        15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10,
        3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5,
        0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15,
        13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9
    }, {
        10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
        13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
        13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
        1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12
    }, {
        7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
        13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9,
        10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
        3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14
    }, {
        2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9,
        14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6,
        4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14,
        11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3
    }, {
        12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
        10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
        9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
        4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13
    }, {
        4,  11, 2,  14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1,
        13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6,
        1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2,
        6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12
    }, {
        13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
        1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
        7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
        2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11
    } };

    private static final byte[] P = {
        16, 7,  20, 21,
        29, 12, 28, 17,
        1,  15, 23, 26,
        5,  18, 31, 10,
        2,  8,  24, 14,
        32, 27, 3,  9,
        19, 13, 30, 6,
        22, 11, 4,  25
    };

    // Permutations relating to subkey generation

    private static final byte[] PC1 = {
        57, 49, 41, 33, 25, 17, 9,
        1,  58, 50, 42, 34, 26, 18,
        10, 2,  59, 51, 43, 35, 27,
        19, 11, 3,  60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7,  62, 54, 46, 38, 30, 22,
        14, 6,  61, 53, 45, 37, 29,
        21, 13, 5,  28, 20, 12, 4
    };

    private static final byte[] PC2 = {
        14, 17, 11, 24, 1,  5,
        3,  28, 15, 6,  21, 10,
        23, 19, 12, 4,  26, 8,
        16, 7,  27, 20, 13, 2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
    };

    private static final byte[] rotations = {
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    };

    // convenience methods for performing the basic permutations.
    
    private static long IP(long src)  { return permute(IP, 64, src);                 } // 64-bit output
    private static long FP(long src)  { return permute(FP, 64, src);                 } // 64-bit output
    private static long E(int src)    { return permute(E, 32, src&0xFFFFFFFFL);      } // 48-bit output
    private static int  P(int src)    { return (int)permute(P, 32, src&0xFFFFFFFFL); } // 32-bit output
    private static long PC1(long src) { return permute(PC1, 64, src);                } // 56-bit output
    private static long PC2(long src) { return permute(PC2, 56, src);                } // 48-bit output

    private static long permute(byte[] table, int srcWidth, long src) {
        long dst = 0;
        for (int i=0; i<table.length; i++) {
            int srcPos = srcWidth - table[i];
            dst = (dst<<1) | (src>>srcPos & 0x01);
        }
        return dst;
    }

    private static byte S(int boxNumber, byte src) {
        // The first and last bits determine which 16-value row to
        // reference, so we transform the 6-bit input into an
        // absolute index based on the following bit shuffle:
        // abcdef => afbcde
        src = (byte) (src&0x20 | ((src&0x01)<<4) | ((src&0x1E)>>1));
        return S[boxNumber-1][src];
    }

    private static long getLongFromBytes(byte[] ba, int offset) {
        long l = 0;
        for (int i=0; i<8; i++) {
            byte value;
            if ((offset+i) < ba.length) {
                value = ba[offset+i];
            } else {
                value = 0;
            }
            l = l<<8 | (value & 0xFFL);
        }
        return l;
    }

    private static void getBytesFromLong(byte[] ba, int offset, long l) {
        for (int i=7; i>=0; i--) {
            if ((offset+i) < ba.length) {
                ba[offset+i] = (byte) (l & 0xFF);
                l = l >> 8;
            } else {
                break;
            }
        }
    }

    private static int feistel(int r, /* 48 bits */ long subkey) {
        // 1. expansion
        long e = E(r);
        // 2. key mixing
        long x = e ^ subkey;
        // 3. substitution
        int dst = 0;
        for (int i=0; i<8; i++) {
            dst>>>=4;
            int s = S(8-i, (byte)(x&0x3F));
            dst |= s << 28;
            x>>=6;
        }
        // 4. permutation
        return P(dst);
    }

    private static long[] createSubkeys(/* 64 bits */ long key) {
        long subkeys[] = new long[16];
        
        // perform the PC1 permutation
        key = PC1(key);
        
        // split into 28-bit left and right (c and d) pairs.
        int c = (int) (key>>28);
        int d = (int) (key&0x0FFFFFFF);
        
        // for each of the 16 needed subkeys, perform a bit
        // rotation on each 28-bit keystuff half, then join
        // the halves together and permute to generate the
        // subkey.
        for (int i=0; i<16; i++) {
            // rotate the 28-bit values
            if (rotations[i] == 1) {
                // rotate by 1 bit
                c = ((c<<1) & 0x0FFFFFFF) | (c>>27);
                d = ((d<<1) & 0x0FFFFFFF) | (d>>27);
            } else {
                // rotate by 2 bits
                c = ((c<<2) & 0x0FFFFFFF) | (c>>26);
                d = ((d<<2) & 0x0FFFFFFF) | (d>>26);
            }
            
            // join the two keystuff halves together.
            long cd = (c&0xFFFFFFFFL)<<28 | (d&0xFFFFFFFFL);
            
            // perform the PC2 permutation
            subkeys[i] = PC2(cd);
        }
        
        return subkeys; /* 48-bit values */ 
    }

    public static long encryptBlock(long m, /* 64 bits */ long key) {
        // generate the 16 subkeys
        long subkeys[] = createSubkeys(key);

        // perform the initial permutation
        long ip = IP(m);
        
        // split the 32-bit value into 16-bit left and right halves.
        int l = (int) (ip>>32);
        int r = (int) (ip&0xFFFFFFFFL);
        
        // perform 16 rounds
        for (int i=0; i<16; i++) {
            int previous_l = l;
            // the right half becomes the new left half.
            l = r;
            // the Feistel function is applied to the old left half
            // and the resulting value is stored in the right half.
            r = previous_l ^ feistel(r, subkeys[i]);
        }
        
        // reverse the two 32-bit segments (left to right; right to left)
        long rl = (r&0xFFFFFFFFL)<<32 | (l&0xFFFFFFFFL);
        
        // apply the final permutation
        long fp = FP(rl);
        
        // return the ciphertext
        return fp;
    }
    
    public static long decryptBlock(long m, /* 64 bits */ long key) {
    	//long subkeys[] = createSubkeys(key);
    	long tempkeys[] = createSubkeys(key);
    	long subkeys[] = new long[tempkeys.length];
        for(int i=0; i<tempkeys.length; i++) {
        	subkeys[tempkeys.length-(i+1)] = tempkeys[i];
        }

        long ip = IP(m);

        int l = (int) (ip>>32);
        int r = (int) (ip&0xFFFFFFFFL);

        for (int i=0; i<16; i++) {
            int previous_l = l;
            l = r;
            r = previous_l ^ feistel(r, subkeys[i]);
        }

        long rl = (r&0xFFFFFFFFL)<<32 | (l&0xFFFFFFFFL);
        long fp = FP(rl);

        return fp;
    }

    public static void encryptBlock(
        byte[] message,
        int messageOffset,
        byte[] ciphertext,
        int ciphertextOffset,
        byte[] key,
        byte[] vector
    ) {
    	long v = getLongFromBytes(vector, 0);
        long m = getLongFromBytes(message, messageOffset) ^ v;
        long k = getLongFromBytes(key, 0);
        long c = encryptBlock(m, k);
        getBytesFromLong(ciphertext, ciphertextOffset, c);
        getBytesFromLong(vector, 0, c);
    }
    
    public static void decryptBlock(
    	byte[] ciphertext,
    	int ciphertextOffset,
    	byte[] plaintext,
   		int plaintextOffset,
    	byte[] key,
    	byte[] vector
    ){
    	long v = getLongFromBytes(vector, 0);
    	long m = getLongFromBytes(ciphertext, ciphertextOffset);
    	long k = getLongFromBytes(key, 0);
    	long c = decryptBlock(m, k) ;
    	getBytesFromLong(plaintext, plaintextOffset, c ^ v);
    	getBytesFromLong(vector, 0, m);
    }

    public static byte[] encrypt(byte[] message, byte[] key, byte[] iv) {
        byte[] ciphertext = new byte[message.length];
        byte[] vector = new byte[iv.length];
        System.arraycopy(iv, 0, vector, 0, iv.length);
        

        // encrypt each 8-byte (64-bit) block of the message.
        for (int i=0; i<message.length; i+=8) {
            encryptBlock(message, i, ciphertext, i, key, vector);
        }
        
        return ciphertext;
    }
    
    public static byte[] decrypt(byte[] ciphertext, byte[] key, byte[] iv) {
    	byte[] plaintext = new byte[ciphertext.length];
    	byte[] vector = new byte[iv.length];
        System.arraycopy(iv, 0, vector, 0, iv.length);
    	
    	for (int i=0; i<ciphertext.length; i+=8) {
    		decryptBlock(ciphertext, i, plaintext, i, key, vector);
    	}
    	return plaintext;
    }
    
    public static byte[] encrypt(byte[] challenge, String password, byte[] iv) {
        return encrypt(challenge, passwordToKey(password), iv);
    }
    
    public static byte[] decrypt(byte[] challenge, String password, byte[] iv) {
    	return decrypt(challenge, passwordToKey(password), iv);
    }

    private static byte[] passwordToKey(String password) {
        byte[] pwbytes = password.getBytes();
        byte[] key = new byte[8];
        for (int i=0; i<8; i++) {
            if (i < pwbytes.length) {
                byte b = pwbytes[i];
                // flip the byte
                byte b2 = 0;
                for (int j=0; j<8; j++) {
                    b2<<=1;
                    b2 |= (b&0x01);
                    b>>>=1;
                }
                key[i] = b2;
            } else {
                key[i] = 0;
            }
        }
        return key;
    }
    
    
    
    //////////////////////////////////////////////////////////////////////
    //
    // Test methods
    //
    // The rest of the file is devoted to some simple test infrastructure
    // for providing confidence in this DES implementation.
    //
    //////////////////////////////////////////////////////////////////////
    
    private static int charToNibble(char c) {
        if (c>='0' && c<='9') {
            return (c-'0');
        } else if (c>='a' && c<='f') {
            return (10+c-'a');
        } else if (c>='A' && c<='F') {
            return (10+c-'A');
        } else {
            return 0;
        }
    }
    private static byte[] parseBytes(String s) {
        s = s.replace(" ", "");
        byte[] ba = new byte[s.length()/2];
        if (s.length()%2 > 0) { s = s+'0'; }
        for (int i=0; i<s.length(); i+=2) {
            ba[i/2] = (byte) (charToNibble(s.charAt(i))<<4 | charToNibble(s.charAt(i+1)));
        }
        return ba;
    }
    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i=0; i<bytes.length; i++) {
            sb.append(String.format("%02X ",bytes[i]));
        }
        return sb.toString();
    }

    public static boolean test(byte[] message,  byte[] expected, String password, byte[] iv) {
        return test(message, expected, passwordToKey(password), iv);
    }
    
    private static int testCount = 0;
    public static boolean test(byte[] message, byte[] expected, byte[] key, byte[] iv) {
        System.out.println("Test #"+(++testCount)+":");
        System.out.println("\tmessage:\t"+	hex(message));
        System.out.println("\tiv:\t\t"+	hex(iv));
        System.out.println("\tkey:\t\t"+	hex(key));
        System.out.println("\texpected:\t"+hex(expected));
        byte[] received = encrypt(message, key, iv);
        System.out.println("\treceived:\t"+	hex(received));
        byte[] plain = decrypt(received, key, iv);
        System.out.println("\tdecryption:\t"+	hex(plain));
        boolean result = Arrays.equals(expected, received) && Arrays.equals(message, plain);
        System.out.println("\tverdict:\t"+(result?"PASS":"FAIL"));
        return result;
    }
    
    public static void main(String[] args) {
        test(
            parseBytes("a4b2 c9ef 0876 c1ce 438d e282 3820 dbde"),
            parseBytes("447C B0AB A9B6 AE88 5A11 28FA 1D74 45CA"),
            "mypass",
            parseBytes("fa60 69b9 85fa 1cf7") //iv
        );
        test(
            parseBytes("f3ed a6dc f8b7 9dd6 5be0 db8b 1e7b a551"),
            parseBytes("CF38 E799 C013 CDA2 DB2C 9A0F 623D EA89"),
            "mypass",
            parseBytes("fa60 69b9 85fa 1cf7") //iv
        );
        test(
            parseBytes("a4b2 c9ef 0876 c1ce 5be0 db8b 1e7b a551"),
            parseBytes("447C B0AB A9B6 AE88 14F4 BA4A CD87 E89F"),
            "mypass",
            parseBytes("fa60 69b9 85fa 1cf7") //iv
        );
        test(
            parseBytes("0123456789ABCDEF"),
            parseBytes("6715B9C9E06FFD47"),
            parseBytes("133457799BBCDFF1"),
            parseBytes("fa6069b985fa1cf7") //iv
        );
    }
}
