package aes;

import java.util.Arrays;

public class AES {
	//cipher key
	private static final byte[] CK = { 
	        (byte)0x2B, (byte)0x28, (byte)0xAB, (byte)0x09,
	        (byte)0x7E, (byte)0xAE, (byte)0xF7, (byte)0xCF, 
	        (byte)0x15, (byte)0xD2, (byte)0x15, (byte)0x4F, 
	        (byte)0x16, (byte)0xA6, (byte)0x88, (byte)0x3C
	};
	
	//for the method mixColumn
	//matrix to be multiplied with the plaintext matrix
	private static final byte[][] MK = {
			{0x2, 0x3, 0x1, 0x1},
			{0x1, 0x2, 0x3, 0x1},
			{0x1, 0x1, 0x2, 0x3},
			{0x3, 0x1, 0x1, 0x2}
	};
	
	private static final byte[][] iMK = {
			{14, 11, 13, 9},
			{9, 14, 11, 13},
			{13, 9, 14, 11},
			{11, 13, 9, 14}
	};
	
	//rcon, to generate the round key
	//10 column cause this code only supports the AES-128
	private static final byte[][] rcon = {
			{0x1, 0, 0, 0},
			{0x2, 0, 0, 0},
			{0x4, 0, 0, 0},
			{0x8, 0, 0, 0},
			{0x10, 0, 0, 0},
			{0x20, 0, 0, 0},
			{0x40, 0, 0, 0},
			{(byte)0x80, 0, 0, 0},
			{0x1b, 0, 0, 0},
			{0x36, 0, 0, 0},
	};
	
	//methods to manage the hex byte - String relationship
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
        		s = s.replace("	", "");
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
    
    	private static String hexblock(byte[] bytes) {
        		StringBuilder sb = new StringBuilder();
        		for (int i=0; i<bytes.length; i++) {
            		sb.append(String.format("%02X ",bytes[i]));
            		if(i%4==3) sb.append("\n");
        		}
        		return sb.toString();
    	}
    
    	//S-box(and its inverse) initializing methods
    	//initializing by converting the String to hex byte
	private static final byte[][] S = new byte[16][16];
	private static final byte[][] Sinv = new byte[16][16];
	private static final String[] sst = {
			"63	7c	77	7b	f2	6b	6f	c5	30	01	67	2b	fe	d7	ab	76",
			"ca	82	c9	7d	fa	59	47	f0	ad	d4	a2	af	9c	a4	72	c0",
			"b7	fd	93	26	36	3f	f7	cc	34	a5	e5	f1	71	d8	31	15",
			"04	c7	23	c3	18	96	05	9a	07	12	80	e2	eb	27	b2	75",
			"09	83	2c	1a	1b	6e	5a	a0	52	3b	d6	b3	29	e3	2f	84",
			"53	d1	00	ed	20	fc	b1	5b	6a	cb	be	39	4a	4c	58	cf",
			"d0	ef	aa	fb	43	4d	33	85	45	f9	02	7f	50	3c	9f	a8",
			"51	a3	40	8f	92	9d	38	f5	bc	b6	da	21	10	ff	f3	d2",
			"cd	0c	13	ec	5f	97	44	17	c4	a7	7e	3d	64	5d	19	73",
			"60	81	4f	dc	22	2a	90	88	46	ee	b8	14	de	5e	0b	db",
			"e0	32	3a	0a	49	06	24	5c	c2	d3	ac	62	91	95	e4	79",
			"e7	c8	37	6d	8d	d5	4e	a9	6c	56	f4	ea	65	7a	ae	08",
			"ba	78	25	2e	1c	a6	b4	c6	e8	dd	74	1f	4b	bd	8b	8a",
			"70	3e	b5	66	48	03	f6	0e	61	35	57	b9	86	c1	1d	9e",
			"e1	f8	98	11	69	d9	8e	94	9b	1e	87	e9	ce	55	28	df",
			"8c	a1	89	0d	bf	e6	42	68	41	99	2d	0f	b0	54	bb	16"
	};
	private static final String[] ist = {
			"52	09	6a	d5	30	36	a5	38	bf	40	a3	9e	81	f3	d7	fb", 
			"7c	e3	39	82	9b	2f	ff	87	34	8e	43	44	c4	de	e9	cb", 
			"54	7b	94	32	a6	c2	23	3d	ee	4c	95	0b	42	fa	c3	4e", 
			"08	2e	a1	66	28	d9	24	b2	76	5b	a2	49	6d	8b	d1	25", 
			"72	f8	f6	64	86	68	98	16	d4	a4	5c	cc	5d	65	b6	92", 
			"6c	70	48	50	fd	ed	b9	da	5e	15	46	57	a7	8d	9d	84", 
			"90	d8	ab	00	8c	bc	d3	0a	f7	e4	58	05	b8	b3	45	06", 
			"d0	2c	1e	8f	ca	3f	0f	02	c1	af	bd	03	01	13	8a	6b", 
			"3a	91	11	41	4f	67	dc	ea	97	f2	cf	ce	f0	b4	e6	73", 
			"96	ac	74	22	e7	ad	35	85	e2	f9	37	e8	1c	75	df	6e", 
			"47	f1	1a	71	1d	29	c5	89	6f	b7	62	0e	aa	18	be	1b", 
			"fc	56	3e	4b	c6	d2	79	20	9a	db	c0	fe	78	cd	5a	f4", 
			"1f	dd	a8	33	88	07	c7	31	b1	12	10	59	27	80	ec	5f", 
			"60	51	7f	a9	19	b5	4a	0d	2d	e5	7a	9f	93	c9	9c	ef", 
			"a0	e0	3b	4d	ae	2a	f5	b0	c8	eb	bb	3c	83	53	99	61", 
			"17	2b	04	7e	ba	77	d6	26	e1	69	14	63	55	21	0c	7d"
	};
	private static final void sinit() {
		for(int i=0; i<16; i++) S[i] = parseBytes(sst[i]);
		for(int i=0; i<16; i++) Sinv[i] = parseBytes(ist[i]);
	}
	
	
	//Round phase 1 - byte substitution
	private static byte[] subByte(byte[] msgblock){
		byte[] res = new byte[msgblock.length];
		String temp = "";
		int a=0, b=0;
		for(int i = 0; i<msgblock.length; i++) {
			//temp = Integer.toHexString(msgblock[i]);
			temp = String.format("%02x", msgblock[i]);
			temp.replaceAll("ffffff", "");
			try {
				a = Integer.parseInt(temp.substring(0, 1), 16);
				b = Integer.parseInt(temp.substring(1), 16);
				res[i] = S[a][b];
			}catch(Exception e) {
				e.printStackTrace();
			}
		}
		return res;
	}
	
	private static byte[] inv_subByte(byte[] cipher) {
		byte[] res = new byte[cipher.length];
		String temp = "";
		int a=0, b=0;
		for(int i = 0; i<cipher.length; i++) {
			temp = String.format("%02x", cipher[i]);
			temp.replaceAll("ffffff", "");
			try {
				a = Integer.parseInt(temp.substring(0, 1), 16);
				b = Integer.parseInt(temp.substring(1), 16);
				res[i] = Sinv[a][b];
			}catch(Exception e) {
				e.printStackTrace();
			}
		}
		return res;
	}
	
	//Round phase 2 - row shift
	private static byte[] shiftRow(byte[] msgblock) {
		byte[] res = new byte[msgblock.length];
		int[] order = {0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14};
		for(int i = 0; i<16; i++) res[i] = msgblock[order[i]];
		return res;
	}
	
	private static byte[] inv_shiftRow(byte[] msgblock) {
		byte[] res = new byte[msgblock.length];
		int[] order = {0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12};
		for(int i = 0; i<16; i++) res[i] = msgblock[order[i]];
		return res;
	}
	
	//Round phase 3 - Column mix
	//This phase would not be executed in the final round
	private static byte[] mixColumn(byte[] b) { 
		for(int i=0; i<4; i++) {
			byte[] temp = {0, 0, 0, 0};
			for(int j=0; j<4; j++) {
				for(int k=0; k<4; k++) {
					temp[j] = (byte) (temp[j] ^ x_time(b[4*k+i], MK[j][k]));
				}
			}
			for(int l=0; l<4; l++) b[4*l+i] = temp[l];
		}
		return b;
	}
	
	private static byte[] inv_mixColumn(byte[] b) { //not completed
		for(int i=0; i<4; i++) {
			byte[] temp = {0, 0, 0, 0};
			for(int j=0; j<4; j++) {
				for(int k=0; k<4; k++) {
					temp[j] = (byte) (temp[j] ^ x_time(b[4*k+i], iMK[j][k]));
				}
			}
			for(int l=0; l<4; l++) b[4*l+i] = temp[l];
		}
		return b;
	}
	
	private static byte x_time(byte b, byte n) {
		int i;
		byte temp = 0, mask = 0x01;

		for (i = 0; i < 8; i++) {
			if ((int) (n & mask)!=0)
				temp ^= b;
			if ((int) (b & 0x80)!=0)
				b = (byte) ((b << 1) ^ 0x1B);
			else
				b <<= 1;
			mask <<= 1;
		}
		return temp;
	}
	private static byte xtime(byte by, int num) {
		byte res = 0;
		byte temp = (byte)(by<<1);
		if(by<0) res = (byte)(temp^27);
		return res;
	}
	
	//Round phase 4, and round initial phase - Round Key addition
	//Cipher key has been initialized in the top of the class block
	private static byte[] addRoundKey(byte[] msgblock) {
		byte[] temp = new byte[msgblock.length];
		for(int i=0; i<16; i++) temp[i] = (byte)(CK[i] ^ msgblock[i]);
		return temp;
	}
	
	private static byte[] addRoundKey(byte[] msgblock, int round) {
		byte[] temp = new byte[msgblock.length];
		for(int i=0; i<16; i++) temp[i] = (byte)(genKey(CK, round)[i] ^ msgblock[i]);
		return temp;
	}
	
	private static byte[] genKey(byte[] prev, int roundlevel){
		if(roundlevel > 10) return null;
		byte[] temp = new byte[prev.length];
		temp = genKeyRound(prev, 0);
		for(int i = 0; i < roundlevel; i++) {
			temp = genKeyRound(temp, i+1);
		}
		return temp;
	}
	
	private static byte[] genKeyRound(byte[] prev, int round) {
		int num = 0;
		byte[] temp = new byte[prev.length];
		byte[] call = {prev[7], prev[11], prev[15], prev[3]};
		call = subByte(call);
		for(int i=0; i<4; i++) {
			temp[4*i] = (byte) (prev[4*i] ^ call[i] ^ rcon[round][i]);
		}
		num = 0;
		for(int i=0; i<3; i++) {
			for(int j=0; j<4; j++) {
				num = 4*j+i;
				temp[num+1] = (byte) (prev[num+1] ^ temp[num]);
			}
		}
		return temp;
	}
	
	private static void encryptBlock(byte[] msg, int msgOffset, byte[] cipher, int cipherOffset) {
		byte[] m = new byte[16];
		System.arraycopy(msg, msgOffset, m, 0, 16);
		
		byte[] temp = addRoundKey(m);
		for(int i = 0; i < 10; i++) {
			temp = subByte(temp);
			temp = shiftRow(temp);
			if(i!=9) temp = mixColumn(temp);
			temp = addRoundKey(temp, i);
		}
		System.arraycopy(temp, 0, cipher, cipherOffset, 16);
	}
	
	private static void decryptBlock(byte[] cipher, int cipherOffset, byte[] plain, int plainOffset) {
		byte[] c = new byte[16];
		System.arraycopy(cipher, cipherOffset, c, 0, 16);
		
		byte[] temp = addRoundKey(c, 9);
		for(int i = 0; i < 10; i++) { //need to fix the order of methods
			temp = inv_shiftRow(temp);
			temp = inv_subByte(temp);
			if(i!=9) {
				temp = addRoundKey(temp, 8-i);
				temp = inv_mixColumn(temp);
			}
			else temp = addRoundKey(temp);
		}
		System.arraycopy(temp, 0, plain, plainOffset, 16);
	}
	
	private static byte[] encrypt(byte[] msg) {
		byte[] cipher = new byte[msg.length];
		
		for (int i=0; i<msg.length; i+=16) encryptBlock(msg, i, cipher, i);
		return cipher;
	}
	
	private static byte[] decrypt(byte[] cipher) {
		byte[] plain = new byte[cipher.length];
		
		for (int i=0; i<cipher.length; i+=16) decryptBlock(cipher, i, plain, i);
		return plain;
	}
	
	private static byte[] padding(byte[] msg) {
		byte pad = (byte)(16 - msg.length % 16);
		byte[] res = new byte[msg.length+pad];
		
		System.arraycopy(msg, 0, res, 0, msg.length);	
		for(int i=0; i<pad; i++) res[msg.length+i] = pad;
		return res;
	}
	
	private static byte[] unpadding(byte[] msg) {
		byte pad = msg[msg.length-1];
		byte[] res = new byte[msg.length-pad];
		boolean flag = true;
		for(int i=0; i<pad; i++) {
			if(pad!=msg[msg.length-(i+1)]) flag=false;
		}
		if(flag) System.arraycopy(msg, 0, res, 0, res.length);	
		return res;
	}
	
	public static void test(byte[] testText) {
		sinit();
		System.out.println("input::\n" + hex(testText));
		byte[] cipher = encrypt(padding(testText));
		System.out.println("cipher::\n" + hex(cipher));
		byte[] plain = unpadding(decrypt(cipher));
		System.out.println("plain::\n" + hex(plain));
	}
	
	public static void main(String args[]) {
		sinit();
		byte[] tester = parseBytes("328831E0435A3137F6309807A88DA234");
		//tester = encryptBlock(tester);
		//tester = padding(tester);
		test(tester);
		//System.out.println(hex(tester));
	}
}
