/*SHA-1*/
#include "../header/Crypt.h"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
using namespace std;



void _SHA_1()
{
	string str;
	string choice;
	while (1) {//one loop
		cout << "Plz ensure the length of data, range is [0..2^(61)],press quit to exit, prese -1 as empty string "" \n>>";
		str.clear();
		cin >> str;
		choice = str;
		lower(choice);
		if (choice == "quit") {
			cout << endl;
			break;
		}
		if (str == "-1")
			str = "";
		while (1) {
			choice.clear();
			cout << "show proc? (y/n)\n>>";
			cin >> choice;
			if (choice[0] == 'y' || choice[0] == 'Y' || choice[0] == 'n' || choice[0] == 'N')
				break;
		}
		/*PAD*/
		int ret = _SHA_1_PAD(str);
		if (ret == 1) {
			cout << "wrong range!" << endl;
			continue;
		}
		/*pre treat*/
		uint32_t str_pos = 0;
		string pre_treat;
		while (str_pos<str.length()) {
			pre_treat += _SHA_1_512bit_pre_treat(str.substr(str_pos, 64));
			str_pos += 64;
		}
		/*rolling*/
		/*initial*/
		string my_H[5];// 0-a 1-b 2-c 3-d 4-e
		for (int x = 0;x < 5;++x) {
			my_H[x] = H0[x];
		}
		str_pos = 0;
		/*roll*/
		while (str_pos < pre_treat.length()) {
			one_512_circle(my_H, pre_treat.substr(str_pos, 80 * 4),choice[0]);
			str_pos += 80 * 4;
		}
		str.clear();
		for (int x = 0; x < 5; ++x) {
			str += my_H[x];
		}
		cout << "Hash value(as a hex types string)" << endl;
		cout << str << endl;//here is the answer
		cout << endl;
	}
}
/*pre bit pad*/
int _SHA_1_PAD(string& str)
{
	
	uint64_t length = str.size() * 8; // 64bit
	int pad;
	if (length > MAX_LENGTH){
		cout << "wrong range!" << endl;
		return EXIT;
	}
	else {
		pad = length % 512;			//makesure each patch'length is 512
		if (pad <= 448) {
			pad = 512 - pad - 8 - 64;	//sub the lengthof str and '1'
			stringstream ss;
			if (pad > 0) {
				
				str += char(128);
				if(pad > 8)
				ss << setw(pad / 8) << setfill('\0') << '\0';
				//ss << "\0";
				str += ss.str();
			}
		}
		else {
			pad = 512 * 2 - pad - 8 - 64;	//sub the lengthof str and '1'
			stringstream ss;
			if (pad > 0) {
				str += char(128);
				if (pad > 8)
					ss << setw(pad / 8) << setfill('\0') << '\0';
				//ss << "\0";
				str += ss.str();
			}
		}
		str += char(length <<  0 >> 56);
		str += char(length <<  8 >> 56);
		str += char(length << 16 >> 56);
		str += char(length << 24 >> 56);
		str += char(length << 32 >> 56);
		str += char(length << 40 >> 56);
		str += char(length << 48 >> 56);
		str += char(length << 56 >> 56);

		return 0;
	}
}

/*pre bit expand inputstr_length = 512bit = 64byte*/
/*
	if 0<=t<=15:
		Wt=Mt;
	else:
		Wt=ROTL^1[(Wt-3)^(Wt-8)^(Wt-14)^(Wt-16)]
*/
string _SHA_1_512bit_pre_treat(string str)
{
	//str = 512bit = 16 * 32bit
	string tmp;//80*32bit
	int i = 16;
	uint32_t block = 0;
	tmp += str;
	while (i < 80) {
		block =   (uint8_t(tmp[(i -  3) * 4 + 3]) + (uint8_t(tmp[(i -  3) * 4 + 2]) << 8) + (uint8_t(tmp[(i -  3) * 4 + 1]) << 16) + (uint8_t(tmp[(i -  3) * 4 + 0]) << 24))
				^ (uint8_t(tmp[(i -  8) * 4 + 3]) + (uint8_t(tmp[(i -  8) * 4 + 2]) << 8) + (uint8_t(tmp[(i -  8) * 4 + 1]) << 16) + (uint8_t(tmp[(i -  8) * 4 + 0]) << 24))
				^ (uint8_t(tmp[(i - 14) * 4 + 3]) + (uint8_t(tmp[(i - 14) * 4 + 2]) << 8) + (uint8_t(tmp[(i - 14) * 4 + 1]) << 16) + (uint8_t(tmp[(i - 14) * 4 + 0]) << 24))
				^ (uint8_t(tmp[(i - 16) * 4 + 3]) + (uint8_t(tmp[(i - 16) * 4 + 2]) << 8) + (uint8_t(tmp[(i - 16) * 4 + 1]) << 16) + (uint8_t(tmp[(i - 16) * 4 + 0]) << 24));
		block = (block << 1) + (block >> 31);
		tmp += char(block >> 24);
		tmp += char(block <<  8 >> 24);
		tmp += char(block << 16 >> 24);
		tmp += char(block << 24 >> 24);
		i++;
	}
	return tmp;
}

void one_512_circle(string my_H[], string pre,char choice)
{
	//my_H 0-a 1-b 2-c 3-d 4-e
	int t = 0;
	string T="555";
	if (choice == 'y' || choice == 'Y')
		cout << "               a            b            c            d            e" << endl;
	for (; t < 80; ++t) {
		T = _8calc(uint32_t(calc8(ROTL_t((my_H[0]), 5)) + ft(my_H[1], my_H[2], my_H[3], t) + calc8(my_H[4]) + Kt(t) + calc4(pre.substr(4 * t, 4)))%MOD);
		my_H[4] = my_H[3];	//e=d
		my_H[3] = my_H[2];	//d=c
		my_H[2] = ROTL_t((my_H[1]), 30); //c = ROTL30(b)
		my_H[1] = my_H[0];//b=a
		my_H[0] = T;//a=T
		if (choice == 'y' || choice == 'Y') {
			cout << "|  t = " << setw(2) << t << " : ";
			for (int t = 0; t < 5; ++t) {
				cout << (my_H[t]) << "  |  ";
			}
			cout << endl;
			cout << "*-------------------------------------------------------------------------*" << endl;
			//system("pause");
		}
	}
	for (int t = 0; t < 5; ++t) {
		my_H[t] = _8calc((calc8(H0[t]) + calc8(my_H[t])) % MOD);
	}
}

uint64_t ft(string x, string y, string z, int t)
{
	uint64_t ret = 0;
	if (t >= 0 && t <= 19){
		ret = (calc8(x) & calc8(y)) | ( ~calc8(x) & calc8(z));//Ch(x,y,z)
	}
	else if (t >= 20 && t <= 39) {
		ret = (calc8(x) ^ calc8(y) ^ calc8(z));//Parity(x,y,z)
	}
	else if (t >= 40 && t <= 59) {
		ret = (calc8(x) & calc8(y)) | (calc8(x) & calc8(z)) | (calc8(y) & calc8(z));//Maj(x,y,z)
	}
	else if (t >= 60 && t <= 79) {
		ret = (calc8(x) ^ calc8(y) ^ calc8(z));//Parity(x,y,z)
	}
	else
		ret = INF;
	return ret;
}

uint64_t Kt(int t)
{
	if (t >= 0 && t <= 19)
		return 0x5a827999;
	else if (t >= 20 && t <= 39)
		return 0x6ed9eba1;
	else if (t >= 40 && t <= 59)
		return 0x8f1bbcdc;
	else if (t >= 60 && t <= 79)
		return 0xca62c1d6;
	else
		return INF;
}

