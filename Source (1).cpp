#include <iostream>
#include <string>
#include <thread>
#include <time.h>
using namespace std;
#define PK 10// initial size for key and for key permutations 
#define PL 8// size of block , input , new generated key , and some permutations 
#define EP 8// Expanded Size
#define numberRounds 2 // number of rounds

//convert hexadecimal to binary -> one char to 4 bits
string getBin(const char& hexdec)
{

	switch (hexdec) {

	case '0': return "0000";

	case '1': return "0001";

	case '2': return "0010";

	case '3': return "0011";

	case '4': return "0100";

	case '5': return "0101";

	case '6': return "0110";

	case '7': return "0111";

	case '8': return "1000";

	case '9': return "1001";

	case 'A':
	case 'a': return "1010";

	case 'B':
	case 'b': return "1011";

	case 'C':
	case 'c': return "1100";

	case 'D':
	case 'd': return "1101";

	case 'E':
	case 'e': return "1110";

	case 'F':
	case 'f': return "1111";

	default: return string();

	}

}

//convert string of hexadecimal to string of binary 
string HexToBin(const string& hexdec)
{
	string k = string();
	for (int i = 0; i < hexdec.length(); i++)k += getBin(hexdec[i]);
	return k;
}

//convert binary to hexadecimal -> 4 bits to one char
char getHexa(const string& bin)
{

	if (bin == "0000")return '0';
	if (bin == "0001")return '1';
	if (bin == "0010")return '2';
	if (bin == "0011")return '3';
	if (bin == "0100")return '4';
	if (bin == "0101")return '5';
	if (bin == "0110")return '6';
	if (bin == "0111")return '7';
	if (bin == "1000")return '8';
	if (bin == "1001")return '9';
	if (bin == "1010")return 'A';
	if (bin == "1011")return 'B';
	if (bin == "1100")return 'C';
	if (bin == "1101")return 'D';
	if (bin == "1110")return 'E';
	if (bin == "1111")return 'F';
	return '\t';

}

/*string BinToHex(const string &bin)
{
	string k=string();
	for(int i=0;i<bin.length();){
	string f=string();
	for(int j=0;j<4;j++,i++){f+=bin[i];} k+=getHexa(f); }
	return k;
}*/

//convert string of binary to string of hexadecimal
string BinToHex(const string& bin)
{
	int l = 0; l = bin.length() % 4;
	string h = string();
	if (l >= 1) {
		for (int i = 0; i < (4 - l); i++) { h += "0"; }
		for (int i = 0; i < l; i++) { h += bin[i]; }
	}
	string K = string(); K.append(bin, l, bin.length());
	string k = string();
	for (int i = 0; i < K.length();) { string f = string(); for (int j = 0; j < 4; j++, i++) { f += K[i]; }  k += getHexa(f); }
	if (l >= 1) return (getHexa(h) + k);
	return k;
}

//one bits XOR other bit
char bitsXOR(const char b1, const char b2)
{
	return (b1 == b2) ? '0' : '1';
}

//string bits XOR other string
string XOR(const string& x, const string& y)
{
	string ans = string();
	for (int i = 0; i < x.length(); i++)ans += bitsXOR(x[i], y[i]);
	return ans;
}

//swap first half of string with second half
string swaP(const string& p)
{
	string k = string();
	string LP = string(), RP = string();
	LP.append(p, 0, (p.length() / 2));
	RP.append(p, (p.length() / 2), p.length());
	k = RP + LP;
	return k;
}

//number of *left circular shift*  key in i rounds
int su(int i)
{
	if (i <= 0)return NULL;
	if (i == 1)return 1;
	return i + su(i - 1);
}

//get binary key
string optemizeKey(const string& key)
{
	string k = string(), g = HexToBin(key);

	if (key.empty()) { int i = 0; while (i++ > PK)k += '0'; return k; }

	if (key.length() >= 3) { k.append(g, (g.length() - PK), g.length()); return k; }

	string Tk = string();
	for (int i = 0; i < (PK - g.length()); i++) { Tk += '0'; }
	k = Tk + g;

	return k;

}

//SDES Cipher basic functions // work with binary representation
string keyRound(const string& key, const int& r); //generate and return key for r rounds 
string KeyGeneration(const string& key, const int& r);//generate and return key for r rounds " calls a previous function "
string ExpandeBits(const string& k);//Expand the half block size to defined Expanded Size
string SBOX(const int& s, const string& b);//definition SBOXES s:mod of box SBOX0-s0- or SBOX1-s1- , b:xyyx : xx : row , yy: column
string functionRound(const string& p, const string& key, const int& r);// feistel cipher function for SDES rounds
string Round(const string& p, const string& key, const int& r);//Rounds
string SDES(const string& p, const string& key, const bool& mood);//Cipher , mood:true->Encryption , mood:false->Decryption

// brute-force attack from least to most
//first way
const char MAX = '1', MIN = '0';
string KEY1 = "0000000000";//size 10 bits
bool newKey(const int& i)
{
	KEY1[i]++;//flips bit from zero to one // flips bit from MIN for MAX
	if (KEY1[i] > MAX)
	{
		KEY1[i] = MIN;//flips bit from one to zero // flips bit from MAX to MIN
		if (i == 0)return false;// end of all possible keys from ( two bits -(MAX-MIN)chars- ) for length of  KEY1 
		return newKey(i - 1);//flips from next bit to first bits // flips from next char to first char
	}
	return true;
}

string brute_force_attackA()
{
	string f = HexToBin("A9");// binary obtained plaintext
	string ff = SDES(f, optemizeKey("282"), true); // binary obtained ciphertext
	//cout<<f<<"\n"; cout<<ff<<" "<<optemizeKey("3DA")<<"\n";
	if (f == SDES(ff, KEY1, false))return BinToHex(KEY1);
	while (newKey(KEY1.length() - 1)) { if (ff == SDES(f, KEY1, true)) {/*cout<<SDES(f,KEY1,true)<<" "<<ff<<" "<<KEY1<<"\n";*/ return BinToHex(KEY1); } }

	return "not found";
}

//second way
string brute_force_attackB()
{

	string f = HexToBin("A9"); // binary obtained plaintext
	string ff = SDES(f, optemizeKey("282"), true); // binary obtained ciphertext

	int num_ascii = 2;
	for (char char1 = '0'; char1 < '2'; char1++) {
	for (int char2 = '0'; char2 < '2'; char2++) {
	for (int char3 = '0'; char3 < '2'; char3++) {
	for (int char4 = '0'; char4 < '2'; char4++) {
	for (int char5 = '0'; char5 < '2'; char5++) {
	for (int char6 = '0'; char6 < '2'; char6++) {
	for (int char7 = '0'; char7 < '2'; char7++) {
	for (int char8 = '0'; char8 < '2'; char8++) {
	for (int char9 = '0'; char9 < '2'; char9++) {
	for (int char10 = '0'; char10 < '2'; char10++) {
	string attempt = string() + (char)char10 + (char)char9 + (char)char8 + (char)char7 + (char)char6 + (char)char5 + (char)char4 + (char)char3 + (char)char2 + (char)char1;
	//cout<<attempt<<"\n";
	if (f == SDES(ff, attempt, false))return BinToHex(attempt);
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return string();
}


//

char fun(int i)
{
	if (i == 0)return '0';
	if (i == 1)return '1';
	if (i == 2)return '2';
	if (i == 3)return '3';
	if (i == 4)return '4';
	if (i == 5)return '5';
	if (i == 6)return '6';
	if (i == 7)return '7';
	if (i == 8)return '8';
	if (i == 9)return'9';
	if (i == 10)return 'A';
	if (i == 11)return 'B';
	if (i == 12)return 'C';
	if (i == 13)return 'D';
	if (i == 14)return 'E';
	if (i == 15)return 'F';
}

int d1 = 0; char d2 = '0';
void fun1()
{
	d2=fun(d1);
}

int d11 = 0; char d22 = '0';
void fun2()
{
	d22=fun(d11);
}

int d111 = 0; char d222 = '0';
void fun3()
{
	d222=fun(d111);
}

string brute_force_attackWithout()
{

	string w = HexToBin("A9"); // binary obtained plaintext
	string ww = SDES(w, optemizeKey("282"), true); // binary obtained ciphertext

	//if (w == SDES(ww, "0000000000", false))return BinToHex("0000000000");

	for (int i = 0; i <= 15; i++) { d1 = i; fun1();
	for (int j = 0; j <= 15; j++) { d11 = j; fun2();
	for (int q = 0; q <= 3; q++)  { d111 = q; fun3();

	string atemp = string();
	atemp += d222;
	atemp += d22;
	atemp += d2;
	//cout <<atemp<< " \n";

	if (w == SDES(ww, optemizeKey(atemp), false))return atemp;

			}
		}
	}

	return "not found";
}

//brute-force attack  Use multi-threading
string brute_force_attackThread()
{
	
	string w = HexToBin("A9"); // binary obtained plaintext
	string ww = SDES(w, optemizeKey("282"), true); // binary obtained ciphertext
	
	//if (w == SDES(ww, "0000000000", false))return BinToHex("0000000000");

	for (int i = 0; i <= 15; i++) { d1 = i; thread f1(fun1); f1.join();
	for (int j = 0; j <= 15; j++) { d11 = j;  thread f2(fun2);  f2.join();
	for (int q = 0; q <= 3; q++) {  d111 = q; thread f3(fun3); f3.join();

	string atemp = string();
	atemp += d222;
	atemp += d22;
	atemp += d2;
	//cout <<atemp<< " \n";

	if (w == SDES(ww, optemizeKey(atemp), false))return atemp; 

	}
	}
	}

	return "not found";
}

void brute_force_attackAllPossibleKey() 
{
	string f = HexToBin("A9");// binary obtained plaintext
	string ff = SDES(f, optemizeKey("3da"), true); // binary obtained ciphertext
	int i = 0;
	if (f == SDES(ff, KEY1, false)) { i++;  cout << BinToHex(KEY1) << "\n"; }
	while (newKey(KEY1.length() - 1)) { if (ff == SDES(f, KEY1, true)) { i++; cout << BinToHex(KEY1) << "\n"; } }

	if (i == 0)cout << "not found \n";

	return;
}

string EBC(string s,string k,const bool& mood)
{
	if (s.empty() || k.empty())return string();

	if ((s.length() % 2) == 1)s = "0" + s; //add padding in most

	string ebc = string();
	int i = 0;

	while (i < s.length()) {
		string r = string();
		r += s[i++];
		r +=s[i++];
		ebc += SDES(HexToBin(r), optemizeKey(k), mood);
	}

	return BinToHex(ebc);
}

void main()
{
	//cout<<HexToBin("A9")<<"\n";
	/*cout<<BinToHex("011000111010000010")<<"\n";
	cout<<BinToHex("111010000010")<<"\n";
	cout<<BinToHex("1010000010")<<"\n";
	cout<<BinToHex("1")<<"\n";
	cout<<BinToHex("0")<<"\n";
	cout<<BinToHex("10")<<"\n";
	cout<<BinToHex("101")<<"\n";
	cout<<BinToHex("1010")<<"\n";
	cout<<BinToHex("10101010")<<"\n";*/
	//cout<<HexToBin("69")<<"\n";
	//cout<<swaP(HexToBin("69"))<<"\n";//10010110
	//cout<<BinToHex("10010110")<<"\n";
	//cout<<su(4)<<"\n";
	//cout<<optemizeKey("282")<<"\n";//1010000010
	//cout<<keyRound("1010000010",1)<<"\n";
	//cout<<keyRound("1010000010",2)<<"\n";
	//cout<<optemizeKey("282")<<"\n";//1010000010
	//cout<<KeyGeneration(optemizeKey("282"),1)<<"\n";
	//cout<<KeyGeneration(optemizeKey("282"),2)<<"\n";
	//cout<<ExpandeBits("1001")<<"\n"; //11000011
	//cout<<XOR("010","010")<<"\n";
	//cout<<XOR("010","101")<<"\n";
	//cout<<SBOX(0,"1101")<<"\n";
	//cout<<SBOX(1,"1101")<<"\n";
	//P=01110010
	//cout<<functionRound("1001",optemizeKey("282"),1)<<"\n";
	// IP=10101001
	//cout<<Round("10101001",optemizeKey("282"),1)<<"\n";
	//cout<< SDES("01110010",optemizeKey("282"),true)<<"\n";//01110111
	//cout<< SDES("01110111",optemizeKey("282"),false)<<"\n";//01110010
	//cout<< SDES("01101001",optemizeKey("282"),true)<<"\n";
	//cout<< SDES("11000111",optemizeKey("282"),false)<<"\n";

	//Decryption 69 with key 3DA
	//string f=SDES(HexToBin("69"),optemizeKey("3DA"),false);//
	//cout<<optemizeKey("3DA")<<"\n";
	//cout<<BinToHex(SDES("01001101",optemizeKey("3DA"),true))<<"\n";
	//cout<<"Decryption 69 : "<<f<<" : "<<BinToHex(f)<<"\n";
	//cout<<BinToHex(SDES(f,optemizeKey("3DA"),true))<<"\n";
	/* f=HexToBin("69");
	 cout<<f<<"\n";
	 cout<<BinToHex(f)<<"\n";*/
	 /*//Encryption Decryption(69) with key 3DA
	 f=SDES(f,optemizeKey("3DA"),true);
	 cout<<"Encryption (Decryption(69))-4D- : "<<f<<" : "<<BinToHex(f)<<"\n";
	 */
	 //Decryption A9 with key 282
	 //f=SDES(HexToBin("A9"),"001111011010",false);
	 //cout<<BinToHex(SDES(f,"001111011010",true))<<"\n";
	 //cout<<"Decryption A9 : "<<f<<" : "<<BinToHex(f)<<"\n";
	 /*
	 //Encryption Decryption(A9) with key 282
	 f=SDES(f,optemizeKey("282"),true);
	 cout<<"Encryption (Decryption(A9))-67- : "<<f<<" : "<<BinToHex(f)<<"\n";*/
	 //cout<<BinToHex("001111011010")<<"\n";
	 //cout<<brute_force_attack1()<<"\n";

	 //cout<<KeyGeneration("0010011010",1)<<"\n";
	 //cout<<KeyGeneration("0010011010",2)<<"\n\n";
	 //cout<<KeyGeneration("1111011010",1)<<"\n";
	 //cout<<KeyGeneration("1111011010",2)<<"\n\n";

	 //cout<<SBOX(0,"1010")<<"\n";
	 //cout<<SBOX(1,"0110")<<"\n";

	 //cout<<functionRound("1001","0010011010",1)<<"\n";
	 //cout<<Round("01011001","0010011010",1)<<"\n";

	 //cout<<functionRound("0010","0010011010",2)<<"\n";
	 //cout<<Round("10010010","0010011010",2)<<"\n";


	 //cout<<functionRound("1001","1111011010",1)<<"\n";
	 //cout<<Round("01011001","1111011010",1)<<"\n";

	 //cout<<functionRound("0010","1111011010",2)<<"\n";
	 //cout<<Round("10010010","1111011010",2)<<"\n";

	 //cout<<SDES("10010110","0010011010",false)<<"\n";
	 //cout<<SDES("10010110","1111011010",false)<<"\n";

	 //
	 //cout<<functionRound("1001","0010011010",2)<<"\n";
	 //cout<<Round("01011001","0010011010",2)<<"\n";

	 //cout<<functionRound("1001","1111011010",2)<<"\n";
	 //cout<<Round("01011001","1111011010",2)<<"\n";

	 //cout<<SDES("10010110",optemizeKey("09A"),false)<<"\n";
	 //cout<<SDES("10101001",optemizeKey("09A"),true)<<"\n\n";

	 //cout<<optemizeKey("09A")<<" "<<optemizeKey("3da")<<"\n";

	 //cout<<SDES("10010110",optemizeKey("3da"),false)<<"\n"; 
	 //cout<<SDES("10101001",optemizeKey("3da"),true)<<"\n";

	/*
	cout<<SDES("10100101","0010010111",true)<<"\n"; //00110110
	cout<<SDES("11010101","0111010001",true)<<"\n"; //01110011
	cout<<SDES("00000000","0000000000",true)<<"\n"; //11110000
	cout<<SDES("11111111","1111111111",true)<<"\n"; //00001111
	*/

	//brute_force_attackAllPossibleKey();

	//cout << EBC("69", "3da", true) << "\n";
	//cout << EBC("69", "3da", false) << "\n";

	/*cout << BinToHex(SDES(HexToBin("69"), optemizeKey("3da"), true) )<< "\n";
	cout << BinToHex(SDES(HexToBin("69"), optemizeKey("3da"), false)) << "\n";*/

	/*string f = HexToBin("A9");// binary obtained plaintext
	string ff = SDES(f, optemizeKey("3da"), true);
	cout << BinToHex(ff) << " "; ff = SDES(f, optemizeKey("3fe"), true); cout << BinToHex(ff) << "\n";

	f = SDES(ff, optemizeKey("3da"), false);
	cout << BinToHex(f) << " "; f = SDES(ff, optemizeKey("3fe"), false); cout << BinToHex(f) << "\n";*/

	cout << "encrypts 69 with key 3da : " << EBC("69", "3da", true) << "\n";
	cout << "decrypts 69 with key 3da : "<< EBC("69", "3da", false) << "\n\n";

	cout << "brute_force_attack binary key level\n";

	cout <<"brute_force_attack first way recursively , Key: "<< brute_force_attackA() << " ";

	// time first way
	clock_t start = clock();
	brute_force_attackA();
	clock_t end = clock();
	double d = ((end - start) / (float)CLOCKS_PER_SEC);
	cout << " Time: " << d << " Sec\n";

	cout <<"brute_force_attack second way loobs , Key: "<<brute_force_attackB() << " ";

	// time second way
	start = clock();
	brute_force_attackB();
	end = clock();
	d = ((end - start) / (float)CLOCKS_PER_SEC);
	cout <<" Time: "<< d << " Sec\n";

	cout << "\nbrute_force_attack hexadecimal key level\n";

	cout << "brute_force_attack third way without multi-threading , Key: " << brute_force_attackWithout() << " ";
	// time second way
	start = clock();
	brute_force_attackWithout();
	end = clock();
	d = ((end - start) / (float)CLOCKS_PER_SEC);
	cout << " Time: " << d << " Sec\n";

	cout <<"brute_force_attack fourth way multi-threading , Key: " << brute_force_attackThread() << " ";
	// time second way
	start = clock();
	brute_force_attackThread();
	end = clock();
	d = ((end - start) / (float)CLOCKS_PER_SEC);
	cout << " Time: " << d << " Sec\n";

	cout << "\nbrute_force_attack for All Possible Key : \n";
	brute_force_attackAllPossibleKey();



}

string keyRound(const string& key, const int& r)
{
	//initial key permutations 
	int P[PK] = { 3,5,2,7,4,10,1,9,8,6 };
	string k = string();
	for (int i = 0; i < PK; i++)k += key[P[i] - 1]; // cout<<k<<"\n";

	for (int ii = 0; ii < su(r); ii++)
	{

		//divide string to two halves
		string LP = string(), RP = string();
		LP.append(k, 0, (PK / 2)); //cout<<LP<<" ";
		RP.append(k, (PK / 2), PK); //cout<<RP<<"\n";

		//circular shift left for 'su(r)' times for first half
		string TLP = string(), TRP = string();
		TLP.append(LP, 1, (PK / 2));
		TLP += LP[0]; //cout<<TLP<<" ";

		//circular shift left for 'su(r)' times for second half
		TRP.append(RP, 1, (PK / 2));
		TRP += RP[0]; //cout<<TRP<<"\n";

		//Merge* two halves shifted*
		k = string();
		k += TLP + TRP;

		//cout<<"-----------------\n";

	}

	//last key permutations 
	int P2[PL] = { 6,3,7,4,8,5,10,9 };
	string TK = string();
	for (int i = 0; i < PL; i++)TK += k[P2[i] - 1];

	return TK; //return key round

}

string KeyGeneration(const string& key, const int& r)
{
	if (!(r >= 1 && r <= numberRounds))return string();// get key in range of rounds

	return  keyRound(key, r);
}

string ExpandeBits(const string& k)
{
	// Expand permutations 
	int EP_[EP] = { 4,1,2,3,2,3,4,1 };
	string TK = string();
	for (int i = 0; i < EP; i++)TK += k[EP_[i] - 1];

	return TK;
}

string SBOX(const int& s, const string& b)
{
	//SBOX_0
	int sb0[4][4] =
	{ {1,0,3,2}
	, {3,2,1,0}
	, {0,2,1,3}
	, {3,1,3,2}
	};

	//SBOX_1
	int sb1[4][4] =
	{ {0,1,2,3}
	, {2,0,1,3}
	, {3,0,1,0}
	, {2,1,0,3}
	};


	//get row and column binary
	string x = string(); x += b[0]; x += b[3];
	string y = string(); y += b[1]; y += b[2];

	int i = -1, j = -1;

	//get row decimal
	if (x == "00")i = 0;
	else
		if (x == "01")i = 1;
		else
			if (x == "10")i = 2;
			else
				if (x == "11")i = 3;

	//get column decimal
	if (y == "00")j = 0;
	else
		if (y == "01")j = 1;
		else
			if (y == "10")j = 2;
			else
				if (y == "11")j = 3;

	if (i == -1 || j == -1)return string();// if occur error

	int g = -1;
	if (s == 0)g = sb0[i][j]; // get SBOX_0 decimal value
	else if (s == 1)g = sb1[i][j]; // get SBOX_1 decimal value

	//convert decimal value to 2 bits binary
	switch (g)
	{
	case 0: return "00";
	case 1: return "01";
	case 2: return "10";
	case 3: return "11";
	default: return string(); // if occur error
	}

	return string(); // if occur error

}

string functionRound(const string& p, const string& key, const int& r)
{
	string ep = ExpandeBits(p);// Expande right part
	string keyR = KeyGeneration(key, r);//generate round key 

	// Expanded right part XOR Round KEY
	string k = XOR(ep, keyR); //cout<<k<<"\n";

	//divide string to two halves
	string LP = string(), RP = string();
	LP.append(k, 0, (k.length() / 2)); // cout<<LP<<" ";
	RP.append(k, (k.length() / 2), k.length()); //cout<<RP<<"\n";

	//merge SBOX_0(firstPart) with SBOX_1(secondPart)
	k = SBOX(0, LP) + SBOX(1, RP); //cout<<SBOX(0,LP)<<" " <<SBOX(1,RP)<<"\n";

	//last function round permutations 
	int P4[(PL / 2)] = { 2,4,3,1 };
	string TK = string();
	for (int i = 0; i < (PL / 2); i++)TK += k[P4[i] - 1];

	return TK;

}


string Round(const string& p, const string& key, const int& r)
{
	string k = string();

	//divide string to two halves
	string LP = string(), RP = string();
	LP.append(p, 0, (p.length() / 2));
	RP.append(p, (p.length() / 2), p.length());

	//merge (firstPart XOR functionRound(second Part)) with second Part
	k = XOR(LP, functionRound(RP, key, r)) + RP;

	return k;
}

string SDES(const string& p, const string& key, const bool& mood)
{
	// Initial Permutations
	int IP[PL] = { 2,6,3,1,4,8,5,7 };
	string k = string();
	for (int i = 0; i < PL; i++)k += p[IP[i] - 1];

	int r = numberRounds + 1;
	for (int i = 1; i <= numberRounds; i++)
	{
		if (mood == true) { r = i; }// Encryption
		else { r--; } // Decryption

		k = Round(k, key, r); //cout<<k<<"\n";

		//swap in all round except last round
		if (i != numberRounds)
			k = swaP(k);
	}

	// Inverse Permutations
	int IPN[PL] = { 4,1,3,5,7,2,8,6 };
	string Tk = string();
	for (int i = 0; i < PL; i++)Tk += k[IPN[i] - 1];

	return Tk;
}


/*
string brute_force_attack(){
  string KEY1;
  int num_ascii=2;
  for (char char1='0'; char1<'2'; char1++) {
   for (int char2=0; char2<'2'; char2++) {
	for (int char3=0; char3<'2'; char3++) {
	 for (int char4=0; char4<'2'; char4++) {
	  string attempt = string()+(char)char1+(char)char2+(char)char3+(char)char4;
	  if (attempt==KEY1) return attempt;
	 }
	}
   }
  }
  cout<<"not found";
}*/

/*

// brute-force attack from most to least
const char MAX = '1', MIN = '0';
string KEY1= "00000";
bool newKey(int i)
{
   KEY1[i]++;//flips bit from zero to one // flips bit from MIN for MAX
  if (KEY1[i] > MAX)
  {
	KEY1[i] = MIN;//flips bit from one to zero // flips bit from MAX to MIN
	if (i==(KEY1.length()-1))return false;// end of all possible keys from ( two bits -(MAX-MIN)chars- ) for length of  KEY1
	return newKey(i + 1);//flips from next bit to first bits // flips from next char to first char
  }
  return true;
}
int brute_force_attack()
{

  while (newKey(0))
 {
  cout<<KEY1<<"\n";
  if("11101"==KEY1){cout<<"true"<<"\n"; return 0;}
 }
  if("0000"==KEY1){cout<<"true"<<"\n"; return 0;}
	return 0;
}

*/

/*

// brute-force attack from least to most
const char MAX = '1', MIN = '0';
string KEY1= "00000";
bool newKey(int i)
{
   KEY1[i]++;//flips bit from zero to one // flips bit from MIN for MAX
  if (KEY1[i] > MAX)
  {
	KEY1[i] = MIN;//flips bit from one to zero // flips bit from MAX to MIN
	if (i==0)return false;// end of all possible keys from ( two bits -(MAX-MIN)chars- ) for length of  KEY1
	return newKey(i - 1);//flips from next bit to first bits // flips from next char to first char
  }
  return true;
}
int brute_force_attack()
{

while (newKey(KEY1.length()-1))
 {
  cout<<KEY1<<"\n";
  if("11101"==KEY1){cout<<"true"<<"\n"; return 0;}
 }
  if("0000"==KEY1){cout<<"true"<<"\n"; return 0;}
	return 0;
}

*/