/* Jeudy Diaz
* CPSC 370
* jdiaz28@live.esu.edu
* DES algorithim capable of multiple rounds of encryption and decryption
* 12/8/2020
*/

#include<iostream>
#include<string>
#include<time.h>
using namespace std;

string globKeys[2];

string xorBinary(string, string);
string hexToBinary(string);
void keyGeneration(string);
string leftShift(string);
string convertDecimalToBinary(int);
int convertBinaryToDecimal(string);
string binaryToHex(string);
string desEncryption(string, int);
void bruteForceKeys(int n, string key, int i, string, time_t* timeBegin);
string noPrintDESEncryption(string pt, int rounds);
void noPrintKeyGeneration(string key);


int main()
{
	string plain = "0x674ADF1B40E538DA";
	cout << "Plaintext: " << plain << endl << endl;
	string key	 = "0x543AB765E71FCA96";
	string pt = hexToBinary(plain);
	string k = hexToBinary(key);
	keyGeneration(k);
	cout << "\nENCRYPTION STARTING...\n\n";
	string ct = desEncryption(pt, 2);
	cout << "Ciphertext is: " << binaryToHex(ct) << "\n----------------------------------------------------------------------------------------------------------------\n\n";
	//Reversing  globKey array for decrytption
		string temp = globKeys[0];
		globKeys[0] = globKeys[1];
		globKeys[1] = temp;
	
	cout << "DECRYPTION STARTING...\n\n";
	string pt1 = desEncryption(ct, 2);
	cout << "Plaintext solution: "<<binaryToHex(pt1) << endl;
	if (pt1 == pt)
	{
		cout << "DES ALGORITHM WORKS!!!!\n\n";
	}
	
	system("pause");
	return 0;
}

void bruteForceKeys(int n, string key, int i, string ct, time_t *timeBegin)
{
	if (i == n) {
		noPrintKeyGeneration(key);
		string temp = globKeys[0];
		globKeys[0] = globKeys[1];
		globKeys[1] = temp;
		string pt = noPrintDESEncryption(ct, 2);
		if(pt == hexToBinary("0x674ADF1B40E538DA"))
		{
			time_t end;
			time(&end);
			time_t elapsed = end - *timeBegin;
			cout << "The brute force process took, " << elapsed << "seconds to crack\n\n";
			return;
		}
		return;
	}

	key += "0";
	bruteForceKeys(n, key, i + 1, ct, timeBegin);

	key += "1";
	bruteForceKeys(n, key, i + 1, ct, timeBegin);
}

//Function to generate keys for each round;
void keyGeneration(string key)
{
	int pc1[56]
	{
		57,49,41,33,25,17,9,
		1,58,50,42,34,26,18,
		10,2,59,51,43,35,27,
		19,11,3,60,52,44,36,
		63,55,47,39,31,23,15,
		7,62,54,46,38,30,22,
		14,6,61,53,45,37,29,
		21,13,5,28,20,12,4
	};

	int pc2[48]
	{
		14,17,11,24,1,5,
		3,28,15,6,21,10,
		23,19,12,4,26,8,
		16,7,27,20,13,2,
		41,52,31,37,47,55,
		30,40,51,45,33,48,
		44,49,39,56,34,53,
		46,42,50,36,29,32
	};

	//Run key through the first permutation and store result
	string permKey = "";
	for(int i = 0; i < 56; i++)
	{
		permKey += key[pc1[i] - 1];
	}
	cout << "Key Permutation 64 bits to 56 bits output: " << binaryToHex(permKey) << endl << endl;

	//Divide key into two halves, left and right
	string left = permKey.substr(0, 28);
	string right = permKey.substr(28, 28);
	string roundKey = "";
	for(int i = 0; i < 2; i++) 
	{
		//Left shift each half one bit
		left = leftShift(left);
		right = leftShift(right);
		string combinedKey = left + right;
		//Final permutation
		for(int i = 0; i < 48; i++)
		{
			roundKey += combinedKey[pc2[i] - 1];
		}
		cout << "Key permutation 56 bits to 48 bits for subkey " << i + 1 <<": " << binaryToHex(roundKey) << endl;
		globKeys[i] = roundKey;
		roundKey = "";
	}
}

//Function for des encryption
string desEncryption(string pt, int rounds)
{
	//Initial permutation table
	int ipc[64] =
	{
		58,50,42,34,26,18,10,2,
		60,52,44,36,28,20,12,4,
		62,54,46,38,30,22,14,6,
		64,56,48,40,32,24,16,8,
		57,49,41,33,25,17,9,1,
		59,51,43,35,27,19,11,3,
		61,53,45,37,29,21,13,5,
		63,55,47,39,31,23,15,7
	};
	//Expansion table
	int expc[48] =
	{
		32,1,2,3,4,5,4,5,
		6,7,8,9,8,9,10,11,
		12,13,12,13,14,15,16,17,
		16,17,18,19,20,21,20,21,
		22,23,24,25,24,25,26,27,
		28,29,28,29,30,31,32,1
	};
	//The post sbox permutation table
	int sboxpc[32] =
	{
		16,7,20,21,29,12,28,17,
		1,15,23,26,5,18,31,10,
		2,8,24,14,32,27,3,9,
		19,13,30,6,22,11,4,25
	};
	//Inverse permutation table
	int invpc[64] =
	{
		40,8,48,16,56,24,64,32,
		39,7,47,15,55,23,63,31,
		38,6,46,14,54,22,62,30,
		37,5,45,13,53,21,61,29,
		36,4,44,12,52,20,60,28,
		35,3,43,11,51,19,59,27,
		34,2,42,10,50,18,58,26,
		33,1,41,9,49,17,57,25
	};
	//Sbox
	int sbox[4][16]
	{	
		2,12,4,0,8,10,11,7,6,5,3,15,14,1,13,9,
		14,11,3,13,4,6,12,1,15,0,5,10,2,9,8,7,
		5,2,1,11,10,13,6,8,4,9,12,14,7,3,0,15,
		10,9,12,6,1,4,2,13,7,15,0,8,11,14,5,3,

	};
	string permPt = "";
	//Initial permutation of the plaintext
	for (int i = 0; i < 64; i++)
	{
		permPt += pt[ipc[i] - 1];
	}
	cout << "Initial permutation result: " << permPt << endl << endl;
	string left = permPt.substr(0, 32);
	string right = permPt.substr(32, 32);
	cout << "Left side : " << left << "\nRight side: " << right << endl << endl;
	// 2 rounds of DES encryption
	for(int i = 0; i < 2; i++)
	{
		string rightExp = "";
		//Expand the right side
		for (int i = 0; i < 48; i++)
		{
			rightExp += right[expc[i] - 1];
		}	
		cout << "Right side expansion permutation: " << rightExp << endl << endl;
		//Xor the right side with the proper key for that round
		string key = globKeys[i];
		cout << "Right expanded xor'ed with round " << i + 1 << " key:\n";
		cout <<  rightExp << "  (Right expanded)\n";
		cout << key << "  (Key)\n------------------------------------------------\n";
		string xorRight = xorBinary(rightExp, key);
		cout << xorRight << "  (xor result)\n\n";
		string output = "";
		cout << "Round " << i + 1 << " sbox substitution results:\n";
		/*
		Take the right xor'ed result and pass it through the s box 6 bits at a time
		sbox[y][z]
		y is the row in the sbox
		z is the column in the sbox
		*/
		for(int i = 0; i < 8; i++)
		{
			//Multiply by 6 to continuously get the next 6 bits in xorRight
			string y = xorRight.substr(i * 6, 1) + xorRight.substr(i * 6 + 5, 1);
			int row = convertBinaryToDecimal(y);
			string z = xorRight.substr(i * 6 + 1, 4);
			int col = convertBinaryToDecimal(z);
			int sboxNum = sbox[row][col];
			string sboxRes = convertDecimalToBinary(sboxNum);
			cout << sboxRes << "\n";
			//Makes sure leading zero's aren't dropped
			while (sboxRes.size() < 4)
			{
				sboxRes = string(1, '0').append(sboxRes);
			}
			output += sboxRes;
		}
		cout << "Sbox Result: " << output << "\n\n";
		string sboxPerm = "";
		//This is the permutation after the sbox
		for(int i = 0; i < 32; i++)
		{
			sboxPerm += output[sboxpc[i] - 1];
		}
		string temp = right;
		right = xorBinary(sboxPerm, left);
		cout << "\nSbox result getting permutated using the p-box for round " << i + 1 <<": " << sboxPerm << "\n\n";
		cout << "p-box result getting xor'ed with initial left side: \n";
		cout << sboxPerm << "  (p-box result)\n";
		cout << left << "  (left side)\n------------------------------------------------\n";
		cout << right << "  (Xor result / Next rounds right side)\n\n";

		left = temp;
	}
	string combined = right + left;
	string ct = "";
	//Putting final result through inverse permutation to get our ciphertext
	for(int i = 0; i < 64; i++)
	{
		ct += combined[invpc[i] - 1];
	}
	return ct;
}

//Function used to xor two binary strings
string xorBinary(string st1, string st2)
{
	string res = "";
	int size = st2.size();
	for (int i = 0; i < size; i++)
	{
		if (st1[i] != st2[i])
		{
			res += "1";
		}
		else 
		{
			res += "0";
		}
	}
	return res;
}

//Function used to convert hexadecimal into a binary string
string hexToBinary(string hex)
{
	string res = "";
	//for loop iterating through each hex string character and converting it to binary form.
	for (int i = 2; i < hex.length(); ++i)
	{
		switch (hex[i])
		{
			case '0': res.append("0000"); break;
			case '1': res.append("0001"); break;
			case '2': res.append("0010"); break;
			case '3': res.append("0011"); break;
			case '4': res.append("0100"); break;
			case '5': res.append("0101"); break;
			case '6': res.append("0110"); break;
			case '7': res.append("0111"); break;
			case '8': res.append("1000"); break;
			case '9': res.append("1001"); break;
			case 'A': res.append("1010"); break;
			case 'B': res.append("1011"); break;
			case 'C': res.append("1100"); break;
			case 'D': res.append("1101"); break;
			case 'E': res.append("1110"); break;	
			case 'F': res.append("1111"); break;
		}
	}
	return res;
}

//Function to convert hex string into binary string
string binaryToHex(string binary)
{
	string res = "0x";
 
	for(int i = 0; i < binary.length()/4; i++)
	{
		if (binary.substr(i * 4, 4) == "0000") 
		{
			res.append("0");
		}
		else if (binary.substr(i * 4, 4) == "0001")
		{
			res.append("1");
		}
		else if (binary.substr(i * 4, 4) == "0010")
		{
			res.append("2");
		}
		else if (binary.substr(i * 4, 4) == "0011")
		{
			res.append("3");
		}
		else if (binary.substr(i * 4, 4) == "0100")
		{
			res.append("4");
		}
		else if (binary.substr(i * 4, 4) == "0101")
		{
			res.append("5");
		}
		else if (binary.substr(i * 4, 4) == "0110")
		{
			res.append("6");
		}
		else if (binary.substr(i * 4, 4) == "0111")
		{
			res.append("7");
		}
		else if (binary.substr(i * 4, 4) == "1000")
		{
			res.append("8");
		}
		else if (binary.substr(i * 4, 4) == "1001")
		{
			res.append("9");
		}
		else if (binary.substr(i * 4, 4) == "1010")
		{
			res.append("A");
		}
		else if (binary.substr(i * 4, 4) == "1011")
		{
			res.append("B");
		}
		else if (binary.substr(i * 4, 4) == "1100")
		{
			res.append("C");
		}
		else if (binary.substr(i * 4, 4) == "1101")
		{
			res.append("D");
		}
		else if (binary.substr(i * 4, 4) == "1110")
		{
			res.append("E");
		}
		else if (binary.substr(i * 4, 4) == "1111")
		{
			res.append("F");
		}
	}
	return res;
}

//Left shift a binary string
string leftShift(string K)
{
	string res = "";

	if (K.size() == 0)
	{
		return res;
	}

	for (int i = 1; i < K.size(); i++)
	{
		res += K[i];
	}
	res += K[0];
	return res;
}

//convert a binary string into a integer
int convertBinaryToDecimal(string binary)
{
	int decimal = 0;
	int counter = 0;
	int size = binary.length();
	for (int i = size - 1; i >= 0; i--)
	{
		if (binary[i] == '1') {
			decimal += pow(2, counter);
		}
		counter++;
	}
	return decimal;
}

//convert an integer into a binary string
string convertDecimalToBinary(int decimal)
{
	string binary;
	while (decimal != 0) {
		binary = (decimal % 2 == 0 ? "0" : "1") + binary;
		decimal = decimal / 2;
	}
	while (binary.length() < 4) {
		binary = "0" + binary;
	}
	return binary;
}
/*
THE FUNCTIONS BELOW ARE THE SAME DECRYPTION AND KEY GENERATION FUNCTIONS WITHOUT THE PRINT STATEMENTS SO IT DOESNT FLOOD THE OUTPUT
*/
string noPrintDESEncryption(string pt, int rounds)
{
	//Initial permutation table
	int ipc[64] =
	{
		58,50,42,34,26,18,10,2,
		60,52,44,36,28,20,12,4,
		62,54,46,38,30,22,14,6,
		64,56,48,40,32,24,16,8,
		57,49,41,33,25,17,9,1,
		59,51,43,35,27,19,11,3,
		61,53,45,37,29,21,13,5,
		63,55,47,39,31,23,15,7
	};
	//Expansion table
	int expc[48] =
	{
		32,1,2,3,4,5,4,5,
		6,7,8,9,8,9,10,11,
		12,13,12,13,14,15,16,17,
		16,17,18,19,20,21,20,21,
		22,23,24,25,24,25,26,27,
		28,29,28,29,30,31,32,1
	};
	//The post sbox permutation table
	int sboxpc[32] =
	{
		16,7,20,21,29,12,28,17,
		1,15,23,26,5,18,31,10,
		2,8,24,14,32,27,3,9,
		19,13,30,6,22,11,4,25
	};
	//Inverse permutation table
	int invpc[64] =
	{
		40,8,48,16,56,24,64,32,
		39,7,47,15,55,23,63,31,
		38,6,46,14,54,22,62,30,
		37,5,45,13,53,21,61,29,
		36,4,44,12,52,20,60,28,
		35,3,43,11,51,19,59,27,
		34,2,42,10,50,18,58,26,
		33,1,41,9,49,17,57,25
	};
	//Sbox
	int sbox[4][16]
	{
		2,12,4,0,8,10,11,7,6,5,3,15,14,1,13,9,
		14,11,3,13,4,6,12,1,15,0,5,10,2,9,8,7,
		5,2,1,11,10,13,6,8,4,9,12,14,7,3,0,15,
		10,9,12,6,1,4,2,13,7,15,0,8,11,14,5,3,

	};
	string permPt = "";
	//Initial permutation of the plaintext
	for (int i = 0; i < 64; i++)
	{
		permPt += pt[ipc[i] - 1];
	}

	string left = permPt.substr(0, 32);
	string right = permPt.substr(32, 32);

	// 2 rounds of DES encryption
	for (int i = 0; i < 2; i++)
	{
		string rightExp = "";
		//Expand the right side
		for (int i = 0; i < 48; i++)
		{
			rightExp += right[expc[i] - 1];
		}

		//Xor the right side with the proper key for that round
		string key = globKeys[i];

		string xorRight = xorBinary(rightExp, key);
		string output = "";

		/*
		Take the right xor'ed result and pass it through the s box 6 bits at a time
		sbox[y][z]
		y is the row in the sbox
		z is the column in the sbox
		*/
		for (int i = 0; i < 8; i++)
		{
			//Multiply by 6 to continuously get the next 6 bits in xorRight
			string y = xorRight.substr(i * 6, 1) + xorRight.substr(i * 6 + 5, 1);
			int row = convertBinaryToDecimal(y);
			string z = xorRight.substr(i * 6 + 1, 4);
			int col = convertBinaryToDecimal(z);
			int sboxNum = sbox[row][col];
			string sboxRes = convertDecimalToBinary(sboxNum);

			//Makes sure leading zero's aren't dropped
			while (sboxRes.size() < 4)
			{
				sboxRes = string(1, '0').append(sboxRes);
			}
			output += sboxRes;
		}
		string sboxPerm = "";
		//This is the permutation after the sbox
		for (int i = 0; i < 32; i++)
		{
			sboxPerm += output[sboxpc[i] - 1];
		}
		string temp = right;
		right = xorBinary(sboxPerm, left);

		left = temp;
	}
	string combined = right + left;
	string ct = "";
	//Putting final result through inverse permutation to get our ciphertext
	for (int i = 0; i < 64; i++)
	{
		ct += combined[invpc[i] - 1];
	}
	return ct;
}

void noPrintKeyGeneration(string key)
{
	int pc1[56]
	{
		57,49,41,33,25,17,9,
		1,58,50,42,34,26,18,
		10,2,59,51,43,35,27,
		19,11,3,60,52,44,36,
		63,55,47,39,31,23,15,
		7,62,54,46,38,30,22,
		14,6,61,53,45,37,29,
		21,13,5,28,20,12,4
	};

	int pc2[48]
	{
		14,17,11,24,1,5,
		3,28,15,6,21,10,
		23,19,12,4,26,8,
		16,7,27,20,13,2,
		41,52,31,37,47,55,
		30,40,51,45,33,48,
		44,49,39,56,34,53,
		46,42,50,36,29,32
	};

	//Run key through the first permutation and store result
	string permKey = "";
	for (int i = 0; i < 56; i++)
	{
		permKey += key[pc1[i] - 1];
	}
	

	//Divide key into two halves, left and right
	string left = permKey.substr(0, 28);
	string right = permKey.substr(28, 28);
	string roundKey = "";
	for (int i = 0; i < 2; i++)
	{
		//Left shift each half one bit
		left = leftShift(left);
		right = leftShift(right);
		string combinedKey = left + right;
		//Final permutation
		for (int i = 0; i < 48; i++)
		{
			roundKey += combinedKey[pc2[i] - 1];
		}
		
		globKeys[i] = roundKey;
		roundKey = "";
	}
}