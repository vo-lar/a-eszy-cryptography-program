/*tools*/
#include "../header/Crypt.h"
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
using namespace std;

void upper(string& str)
{
	for (auto& x : str) {
		x = toupper(x);
	}
}

void lower(string& str)
{
	for (auto& x : str) {
		x = tolower(x);
	}
}

/*calc 4,eg (00101111 11111101 11111111 11111111)->2ffeffff*/
uint32_t calc4(string s)
{
	if (s.length() != 4) {
		cout << "wrong4!" << endl;
		return -1;
	}
	else {
		uint8_t tmp;
		string str;
		for (int i = 0; i < 4; ++i) {
			tmp = (uint8_t(s[i]) >> 4);
			if (tmp < 10)
				tmp += '0';
			else
				tmp += ('a' - 10);
			str += tmp;
			tmp = (uint8_t((s[i]) << 4) >> 4);
			if (tmp < 10)
				tmp += '0';
			else
				tmp += ('a' - 10);
			str += tmp;
		}
		uint32_t ret;
		ret = calc8(str);

		return ret;
	}
	
}


/*calc 8,eg 0x66666666*/
uint32_t calc8(string s)
{
	if (s.length() != 8) {
		cout << "wrong8!" << endl;
		return -1;
	}
	else {
		string str;
		for (int i = 0; i < 8; ++i) {
			if (uint16_t(s[i]) <= '9' && uint8_t(s[i]) >= '0')
				str += (s[i] - '0');
			else if (uint8_t(s[i]) <= 'f' && uint8_t(s[i]) >= 'a')
				str += (s[i] - 'a' + 10);
			else
				str += -1;
		}
		uint32_t ret;
		ret = (uint8_t(str[7]) <<  0) + (uint8_t(str[6]) <<  4) + (uint8_t(str[5]) << 8) + (uint8_t(str[4]) << 12)
			+ (uint8_t(str[3]) << 16) + (uint8_t(str[2]) << 20) + (uint8_t(str[1]) << 24) + (uint8_t(str[0]) << 28);
		return ret;
	}
}

string _8calc(uint64_t t)
{
	string str;
	stringstream ss;
	ss << setbase(16) << t;
	str += ss.str();
	if (str.length() > 8)
		cout << "something wrong in 8calc" << endl;

	else if (str.length() < 8)
	{
		int tmp = 8 - str.length();
		ss.str("");
		ss << setbase(tmp) << setfill('0')<<setw(8 - str.length()) << '0';
		str = ss.str() + str;
	}
	return str;
}

/*print inner bit*/
void identify(string str)
{
	stringstream ss;
	cout << "str_length=" << str.size() << endl;
	int index = 0;
	for (auto x : str) {
		cout << setw(4) << index++ << ":" << "";
		uint8_t mask = 0x80;
		while (mask) {
			cout << !!(x & mask);
			mask >>= 1;
		}
		cout << endl;
	}
}

/*ROTL*/
string ROTL_t(string str, int t)
{
	string tmp;
	uint32_t i = calc8(str);
	i = (i << t) + (i >> (str.length() * 4 - t));
	tmp = _8calc(i);
	return tmp;
}
