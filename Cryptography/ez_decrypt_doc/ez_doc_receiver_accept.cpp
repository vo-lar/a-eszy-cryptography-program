/*CA sender*/

#include <fstream>
#include "../header/Crypt.h"
#include "../header/Crypt_doc.h"


void _CA_receiver_2nd()
{
	uint32_t i;
	string msg;
	string str;
	string c1;
	string c2;
	ZZ p(0), q(0), a(0), n(0);
	cout << "Plz insure the sender.txt in dir" << endl;
	cout << "press enter to continue" << endl;
	system("pause>nul");
	fstream fin;
	fin.open("sender.txt", ios::binary | ios::in);
	if (!fin.is_open()) {
		cout << "can't open the file" << endl;
		fin.close();
		return;
	}
	else {
		while ((fin.get()) != EOF)
		{
			fin.seekg(-1, ios::cur);
			char ch = fin.get();
			msg += ch;
		}
		fin.close();
	}
	//as msg=c1:xxx \n c2:xxx aluc from 3th
	i = 3;
	fin.open("temp.txt", ios::out | ios::binary);

	while (i < msg.length()) {
		if (msg[i] == 'c') {
			if (i + 1 < msg.length() && msg[i + 1] == '2') {
				if (i + 2 < msg.length() && msg[i + 2] == ':') {
					i++;
					break;
				}
			}
			else {
				fin << msg[i];
				c1 += msg[i];
				i++;
			}
		}
		else {
			fin << msg[i];
			c1 += msg[i];
			i++;
		}
	}
	fin.close();
	i += 2;
	while (i < msg.length()) {		
		c2 += msg[i];
		i++;
	}
	/*rsa*/
	msg.clear();
	cout << "Plz ensure \"cilent.txt\" in the same dir" << endl;
	cout << "press enter to continue" << endl;
	system("pause>nul");
	fin.open("cilent.txt", ios::binary | ios::in);
	
	if (!fin.is_open()) {
		cout << "can't open the file" << endl;
		fin.close();
		return;
	}
	else {
		while ((fin.get()) != EOF)
		{
			fin.seekg(-1, ios::cur);
			char ch = fin.get();
			msg += ch;
		}
		fin.close();
	}
	i = 0;
	str.clear();
	while (i < msg.length()) {
		if (msg[i] != ':') {
			i++;
			continue;
		}
		i+=2;
		break;
	}
	while (i < msg.length()) {
		if (msg[i] == 0x0D || msg[i] == 0x0A) {
			i++;
			break;
		}
		str += msg[i];
		i++;
	}
	for (auto x : str) {
		q = q * 10 + (x >= 'a' ? x - 'a' + 10 : x - '0');
	}
	str.clear();
	while (i < msg.length()) {
		if (msg[i] != ':') {
			i++;
			continue;
		}
		i += 2;
		break;
	}
	while (i < msg.length()) {
		if (msg[i] == 0x0D || msg[i] == 0x0A) {
			i++;
			break;
		}
		str += msg[i];
		i++;
	}
	for (auto x : str) {
		p = p * 10 + (x >= 'a' ? x - 'a' + 10 : x - '0');
	}
	str.clear();
	while (i < msg.length()) {
		if (msg[i] != ':') {
			i++;
			continue;
		}
		i += 2;
		break;
	}
	while (i < msg.length()) {
		if (msg[i] == 0x0D || msg[i] == 0x0A) {
			i++;
			break;
		}
		str += msg[i];
		i++;
	}
	for (auto x : str) {
		a = a * 10 + (x >= 'a' ? x - 'a' + 10 : x - '0');
	}
	n = p * q;
	ZZ temp;
	ZZ ans;
	ZZ cnt(1);

	stringstream tmp;
	string plaintext;
	uint32_t x = 0;
	while (x < c2.length()) {
		if (c2[x] == '\n') {
			++x;
			continue;
		}
		temp = 0;
		cnt = 1;
		ans = 0;
		tmp.str("");
		char ch = 0;
		while (x < c2.length() && c2[x] != '\n') {
			temp = (temp * 10 + c2[x] - '0');
			x++;
		}
		ans = square_multi(temp, a, n);
		while (cnt < ans) {
			cnt *= 256;
		}
		cnt /= 256;
		while (cnt != 0)
		{
			tmp.str("");
			tmp << (ans / cnt);
			ch = 0;
			for (auto x : tmp.str()) {
				ch = ch * 10 + x - '0';
			}
			plaintext += ch;
			ans %= cnt;
			cnt /= 256;
		}
	}
	cout << "KEY = " << plaintext.substr(0, 32) << endl;
	cout << "IV  = " << plaintext.substr(33, 32) << endl;
	
	cout << "Plz ensure the infile \"temp.txt\" in dir" << endl;
	_AES_in_CBC("d", "de_c1.txt");
	cout << "c1->de_c1.txt" << endl;
	fin.open("de_c1.txt", ios::binary | ios::in);
	msg.clear();
	if (!fin.is_open()) {
		cout << "can't open the file" << endl;
		fin.close();
		return;
	}
	else {
		while ((fin.get()) != EOF)
		{
			fin.seekg(-1, ios::cur);
			char ch = fin.get();
			msg += ch;
		}
		fin.close();
	}
	string MSG, SIG, N, B, SHA_1;
	//MSG
	i = 4;
	read_file(i, msg, "sig:", MSG);
	//SIG
	read_file(i, msg, "var:", SIG);
	i += 2;
	//N
	while (i < msg.length()) {
		if (msg[i] == 'b') {
			if (i + 1 < msg.length() && msg[i + 1] == ':') {				
				i += 2;
				break;				
			}
			else {
				N += msg[i];
				i++;
			}
		}
		else {
			N += msg[i];
			i++;
		}
	}
	//B
	read_file(i, msg, "SHA-", B);
	i++;
	while (i < msg.length()) {
		SHA_1 += msg[i];
		i++;
	}

	if (false) {
		cout << "MSG:" << MSG << endl;
		cout << "SIG:" << SIG << endl;
		cout << "N:" << N << endl;
		cout << "B:" << B << endl;
		cout << "SHA_1:" << SHA_1 << endl;
	}
	if (ez_sha_1("msg:" + MSG + "sig:" + SIG + "var:" + "n:" + N + "b:" + B) == SHA_1) {
		cout << "Sender's ca is correct" << endl;
	}
	else {
		cout << "------------------------------------------------------" << endl;
		cout << "msg:" + MSG + "sig:" + SIG + "var:" + "n:" + N + "b:" + B << endl;
		cout << "------------------------------------------------------" << endl;
		cout << ez_sha_1("msg:" + MSG + "sig" + SIG + "var:" + "n:" + N + "b:" + B) << endl;
		cout << SHA_1;
		cout << "Sender's ca is wrong!" << endl;
		return;
	}
	ZZ sender_n(0), sender_b(0);
	for (auto m : N) {
		sender_n = sender_n * 10 + (m > 'a' ? m - 'a' + 0x0a : m - '0');
	}
	for (auto m : B) {
		sender_b = sender_b * 10 + (m > 'a' ? m - 'a' + 0x0a : m - '0');
	}
	string correct_SHA_m = ez_sha_1(MSG);
	plaintext.clear();
	x = 0;
	while (x < SIG.length()) {
		if (SIG[x] == '|') {
			++x;
			continue;
		}
		temp = 0;
		cnt = 1;
		ans = 0;
		tmp.str("");
		char ch = 0;
		while (x < SIG.length() && SIG[x] != '|') {
			temp = (temp * 10 + SIG[x] - '0');
			x++;
		}
		ans = square_multi(temp, sender_b, sender_n);
		while (cnt < ans) {
			cnt *= 256;
		}
		cnt /= 256;
		while (cnt != 0)
		{
			tmp.str("");
			tmp << (ans / cnt);
			ch = 0;
			for (auto x : tmp.str()) {
				ch = ch * 10 + x - '0';
			}
			plaintext += ch;
			ans %= cnt;
			cnt /= 256;
		}
	}
	if (false) {
		cout << "plaintext" << endl;
		cout << plaintext << endl;
		cout << "correct_SHA(m)" << endl;
		cout << correct_SHA_m << endl;
	}
	if (plaintext == correct_SHA_m) {
		cout << "¡Ì" << endl;
		cout << "Message confirmation from Sender" << endl;
	}
	else {
		cout << "x" << endl;
		cout << "The message is not from Sender" << endl;
	}
}

void read_file(uint32_t &i,string msg, const char signal[],string &ret) {
	while (i < msg.length()) {
		if (msg[i] == signal[0]) {
			if (i + 1 < msg.length() && msg[i + 1] == signal[1]) {
				if (i + 2 < msg.length() && msg[i + 2] == signal[2]) {
					if (i + 3 < msg.length() && msg[i + 3] == signal[3]) {
						i += 4;
						break;
					}
					else {
						ret += msg[i];
						i++;
					}
				}
				else {
					ret += msg[i];
					i++;
				}
			}
			else {
				ret += msg[i];
				i++;
			}
		}
		else {
			ret += msg[i];
			i++;
		}
	}
}
