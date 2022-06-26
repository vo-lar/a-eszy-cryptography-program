/*CA sender*/
#include "../header/Crypt.h"
#include "../header/Crypt_doc.h"
#include <fstream>
#include "../header/Crypt_RSA.h"

void _CA_sender()
{
	string sender;
	ZZ n, b;
	//ca
	string CA = "";
	string ID = "";
	string s = "";
	stringstream ss;
	string TA = "Personal TA in Tongji,shanghai";
	string str;
	uint16_t flag = 0;
	fstream fin;
	string msg;
	ZZ sig(0);
	unsigned i = 0;

	/*authen*/
	n = 0; b = 0; flag = 0;
	string ID_read = "";
	//param
	cout << "Plz insure the filename is \"CA.txt\"" << endl;
	cout << "press enter to continue" << endl;
	system("pause>nul");
	fin.open("CA.txt", ios::in | ios::binary);
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
	//ID
	while (i < msg.length()) {
		if (msg[i] == '\r' || msg[i] == '\n') {
			i++;
			continue;
		}
		if (msg[i] == 'v')
			break;
		ID += msg[i];
		i++;
	}
	//ver
	while (i < msg.length() && msg[i] != 'n') {
		i++;
	}
	while (i < msg.length()) {
		if (msg[i] == '\r' || msg[i] == '\n' || msg[i] == ':' || msg[i] == 'n') {
			i++;
			continue;
		}
		if (msg[i] == 'b') {
			i++;
			break;
		}
		n = n * 10 + msg[i] - '0';
		i++;
	}
	while (i < msg.length()) {
		if (msg[i] == '\r' || msg[i] == '\n' || msg[i] == ':') {
			i++;
			continue;
		}
		if (msg[i] == 's') {
			i++;
			break;
		}
		b = b * 10 + msg[i] - '0';
		i++;
	}
	while (i < msg.length()) {
		if (msg[i] == '\r' || msg[i] == '\n' || msg[i] == ':') {
			i++;
			continue;
		}
		if (msg[i] == 'T') {
			break;
		}
		sig = 0;
		ss.str("");
		while (msg[i] != '|') {
			sig = sig * 10 + msg[i] - '0';
			i++;
		}
		ss << square_multi(sig, b, n);
		unsigned t = 0;
		while (2 * t + 1 < ss.str().length()) {
			ID_read += ((ss.str()[2 * t] - '0') * 10 + (ss.str()[2 * t + 1] - '0'));
			t++;
		}
		i++;
	}
	string tmp;
	for (auto m : ez_sha_1(ID)) {
		tmp += m / 16 + '0';
		tmp += m % 16 + '0';
	}
	ss.str("");
	ss << n;
	tmp += '$' + ss.str();
	ss.str("");
	ss << b;
	tmp += '$' + ss.str();
	if (ID_read == tmp) {
		cout << endl << "The CA is accepted" << endl << endl;
	}
	else {
		cout << "The CA is not authenticated" << endl;
		return;
	}
	/*sender's rsa key*/
	ZZ sender_p, sender_q, sender_a, sender_n, sender_b, sender_phi_n;
	uint16_t len = 0;
	while (1) {
		cout << "Plz choose the length of p/q, 512 or 1024\n>>";
		cin >> len;//bit
		if (len == 512 || len == 1024) {
			break;//64byte or 128byte
		}
		else {
			cout << "the length is wrong!!!" << endl;
		}
	}
	/*get p and q*/
	cout << "generating the parameters,plz wait for minutes" << endl;
	while (1) {
		sender_q = RandomLen_ZZ(len);
		if (sender_q % 2 && Miller_Rabin(sender_q)) {
			break;
		}
	}
	while (1) {
		sender_p = RandomLen_ZZ(len);
		if (sender_p != sender_q && sender_p % 2 && Miller_Rabin(sender_p)) {
			break;
		}
	}
	sender_n = sender_q * sender_p;
	sender_phi_n = (sender_q - 1) * (sender_p - 1);
	while (1) {
		sender_b = RandomPrime_ZZ(len / 128 * 5);//like 0x10001
		if (GCD(sender_b, sender_phi_n) == 1)
			break;
	}
	sender_a = InvMod(sender_b, sender_phi_n);
	fin.open("sender_key.txt", ios::binary | ios::out);
	fin << "-----BEGIN PUBLIC KEY-----\n";
	fin << "n : " << sender_n << endl;
	fin << "b : " << sender_b << endl;
	fin << "-----END PUBLIC KEY-----\n\n";
	fin << "-----BEGIN PRIVATE KEY-----\n";
	fin << "q : " << sender_q << endl;
	fin << "p : " << sender_p << endl;
	fin << "a : " << sender_a << endl;
	fin << "-----END PRIVATE KEY-----\n";
	fin.close();
	cout << "The key have writen into sender_key.txt" << endl;
	/*read msg*/
	cout << "Plz input the filename of message\n>>";
	str.clear();
	msg.clear();
	cin >> str;
	/*sha-1 and sig*/
	fin.open(str, ios::in | ios::binary);
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
	//cout << msg << endl;
	
	string sha_1 = ez_sha_1(msg);
	string signiture;
	ZZ temp;
	i = 0;
	while (i < sha_1.length()) {
		ss.str("");
		ZZ calc(0);
		ss << sha_1.substr(i, min(unsigned(16), sha_1.length() - i));//128bit(16 byte)->(32 byte)256bit
		for (unsigned j = 0; j < ss.str().length(); j++) {
			calc = calc * 256 + ss.str()[j];
		}
		ss.str("");
		ss << square_multi(calc, sender_a, sender_n) << '|';
		signiture += ss.str();
		i += 16;
	}
	fin.open("AES_sender.txt", ios::binary | ios::out);
	ss.str("");
	ss << "msg:" << msg << "sig:" << signiture << "var:" << "n:" << sender_n << "b:" << sender_b;
	string _sha = ez_sha_1(ss.str());
	ss << "SHA-1" << _sha;
	fin << ss.str();
	fin.close();
	cout << "the AES string has writen into AES_sender.txt" << endl;
	/*AES*/
	//c1
	cout << "c1->c1.txt" << endl;
	_AES_in_CBC("e","c1.txt");
	
	cout << "Plz insure \"aes_cbc_key.enc\" and \"c1.txt\" in the same dir" << endl;
	cout << "press enter to continue" << endl;
	system("pause>nul");
	
	sender += "c1:";
	fin.open("c1.txt", ios::in | ios::binary);
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
			sender += ch;
		}
		fin.close();
	}

	//c2
	str.clear();
	fin.open("aes_cbc_key.enc", ios::in | ios::binary);
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
			str += ch;
		}
		fin.close();
	}
	i = 0;
	string Rev_K;
	string IV;
	ZZ AES_key(0);
	while (str[i] != '\n') {
		i++;
	}
	i++;
	while (str[i] != '\n') {
		Rev_K += str[i];
		i++;
	}
	i++;
	while (str[i] != '\n') {
		i++;
	}
	i++;
	while (str[i] != '\n') {
		IV += str[i];
		i++;
	}
	Rev_K += ' '+IV;
	i = 0;
	string c2;
	while (i < Rev_K.length()) {
		ss.str("");
		ZZ calc(0);
		ss << Rev_K.substr(i, min(unsigned(16), Rev_K.length() - i));//128bit(16 byte)->(32 byte)256bit
		for (unsigned j = 0; j < ss.str().length(); j++) {
			calc = calc * 256 + ss.str()[j];
		}
		ss.str("");
		ss << square_multi(calc, b, n) << '\n';
		c2 += ss.str();
		i += 16;
	}
	sender += "c2:";
	sender += c2;
	//write
	fin.open("sender.txt", ios::binary | ios::out);
	fin << sender;
	fin.close();
	cout << "The file has writen into sender.txt" << endl;
}
