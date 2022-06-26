/*a simple Cryptography Certificate*/
#include "../header/Crypt.h"
#include "../header/Crypt_RSA.h"
#include <fstream>
#include <string>
void _EZ_CA(string doc)
{
	string mod;
	while (1) {//one loop
		if (doc == "") {
			cout << "Plz input the mod,certificate or verification,press quit to exit\n>>";
			mod.clear();
			cin >> mod;
			lower(mod);
			if (mod == "quit") {
				cout << "exit!" << endl;
				break;
			}
		}
		else
			mod = doc;
		ZZ p, q, a, n, b, phi_n;
		string CA = "";
		string ID = "";
		string s = "";
		stringstream ss;
		string TA = "Personal TA in Tongji,shanghai";
		string str;
		uint16_t flag = 0;
		char ch;
		if (mod[0] == 'c') {
			while (1) {
				cout << "Plz choose the length of p/q, 512 or 1024\n>>";
				cin >> flag;//bit
				if (flag == 512 || flag == 1024) {
					break;//64byte or 128byte
				}
				else {
					cout << "wrong length." << endl;
				}
			}
			cout << "generating the parameters.waiting for minutes." << endl;
			/*generate*/
			while (1) {
				q = RandomLen_ZZ(flag);
				if (q % 2 && Miller_Rabin(q)) {
					break;
				}
			}
			while (1) {
				p = RandomLen_ZZ(flag);
				if (p != q && p % 2 && Miller_Rabin(p)) {
					break;
				}
			}
			n = q * p;
			phi_n = (q - 1) * (p - 1);
			while (1) {
				b = RandomPrime_ZZ(flag / 128 * 5);//like 0x10001 4bit*5
				if (GCD(b, phi_n) == 1)
					break;
			}
			a = InvMod(b, phi_n);
			//generate
			{
				fstream fin;
				fin.open("TA.txt", ios::binary | ios::out);
				fin << "-----BEGIN PUBLIC KEY-----\n";
				fin << "n : " << n << endl;
				fin << "b : " << b << endl;
				fin << "-----END PUBLIC KEY-----\n";
				fin.close();
				fin.open("cilent.txt",  ios::out);
				fin << "-----BEGIN PRIVATE KEY-----\n";
				fin << "q : " << q << endl;
				fin << "p : " << p << endl;
				fin << "a : " << a << endl;
				fin << "-----END PRIVATE KEY-----\n";
				fin.close();
				cout << "Done.\nPUBLIC-KEY in TA.txt /*******/ PRIVATE-KEY in cilent.txt" << endl;
			}
			//ID
			{
				/*ID*/
				//PID
				cout << "Plz input your PID : \n>>";
				cin >> str;
				ID += str + ' ';
				while (getchar() != '\n');
				//name
				cout << "Plz input your name : \n>>";
				while (1) {
					ch = cin.get();
					if (ch == '\n')
						break;
					ID += ch;
				}
				ID += ' ';
				//date
				cout << "Plz input your date of birth,like 2000-1-1 : \n>>";
				cin >> str;
				ID += str + ' ';
				CA += ID + '\n';
			}
			//ver and sig
			{
				int temp = 0;
				ZZ calc;
				ZZ ans;
				stringstream block;
				string tmp;
				int i = 0;
				str.clear();
				CA += "ver : ";
				tmp = ez_sha_1(ID);//20
				for (auto m : tmp) {
					str += m / 16 + '0';
					str += m % 16 + '0';
				}
				ss << n;
				str += '$';
				str += ss.str();
				CA += "n:" + ss.str()+'\n';
				ss.str("");
				ss << b;
				str += '$';
				str += ss.str();
				CA += "b:" + ss.str() + '\n';
				ss.str("");
				cout << "The signature is Nopadding. 128bit as one block. Divided by \"|\" a->97" << endl;
				CA += "s:";
				while (i < str.length()) {
					ss.str("");
					calc = 0;
					ss << str.substr(i, min(unsigned(16), str.length() - i));//128bit(16 byte)->(32 byte)256bit
					for (unsigned j = 0; j < ss.str().length(); j++) {
						calc = calc * 10 + ss.str()[j] / 10;
						calc = calc * 10 + ss.str()[j] % 10;
					}
					block.str("");
					block << square_multi(calc, a, n) << '|';
					CA += block.str();
					i += 16;
				}
				CA += '\n';
			}
			//ID(TA) flag
			{
				CA += "TA:" + TA + '\n';
				CA += "flag : " + to_string(flag) + '\n';
			}
			cout << "Writen into CA.txt" << endl;
			fstream fout;
			fout.open("CA.txt", ios::out | ios::binary);
			fout << CA;
			fout.close();
			cout << "Done.\n" << endl;
		}
		else if (mod[0] == 'v') {
			fstream fin;
			string msg;
			ZZ sig(0);
			unsigned i = 0;
			n = 0; b = 0; flag = 0;
			string ID_read = "";
			//param
			cout << "Plz input the CA\n>>";
			cin >> str;
			fin.open(str, ios::in | ios::binary);
			if (!fin.is_open()) {
				cout << "can't open the file" << endl;
				fin.close();
				continue;
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
				cout << "¡Ì" << endl;
				cout << "The CA is accepted" << endl;
				continue;
			}
			else{
				cout << "The CA is not authenticated" << endl;
			}
		}
		else
		{
			cout << "wrong mod" << endl;
			continue;
		}
		if (doc != "")
			break;
	}
}
