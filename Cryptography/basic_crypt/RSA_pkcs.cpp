/*RSA_PKCS implementation*/
/*Need to achieve with NTL lib, http://www.shoup.net/ntl */
#include "../header/Crypt.h"
#include "../header/Crypt_RSA.h"
#include <fstream>
#include <Windows.h>
using namespace std;
void _RSA_PKCS()
{
	string mod;
	uint16_t len = 0;
	string filename;
	fstream fin;
	while (1) {//one loop
		cout << "Plz choose the mod(signature or verification or generate_key), prese quit to exit \n>>";
		mod.clear();
		filename.clear();
		cin >> mod;
		lower(mod);
		ZZ p, q, a, n, b, phi_n;
		string msg;
		
		if (mod == "quit") {
			cout << endl;
			break;
		}
		else if (mod[0] == 'g') {
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
				q = RandomLen_ZZ(len);
				if (q % 2 && Miller_Rabin(q)) {
					cout << "q : " << q << endl;
					break;
				}
			}
			while (1) {
				p = RandomLen_ZZ(len);
				if (p != q && p % 2 && Miller_Rabin(p)) {
					cout << "p : " << p << endl;
					break;
				}
			}

			n = q * p;
			phi_n = (q - 1) * (p - 1);
			while (1) {
				b = RandomPrime_ZZ(len / 128 * 5);//like 0x10001
				if (GCD(b, phi_n) == 1)
					break;
			}
			a = InvMod(b, phi_n);

			Sleep(1000);
			cout << "n = q * p = " << n << endl;
			Sleep(1000);
			cout << "phi_n = (q - 1) * (p - 1) = " << phi_n << endl;
			Sleep(1000);
			cout << "The random b = 0x" << setbase(16) << conv<int>(b) << endl;
			cout << "The conv a = 0x" << setbase(16) << conv<int>(a) << endl;

			fstream fin;
			fin.open("pub_key.txt", ios::binary | ios::out);
			fin << "-----BEGIN PUBLIC KEY-----\n";
			fin << "n : " << n << endl;
			fin << "b : " << b << endl;
			fin << "-----END PUBLIC KEY-----\n";
			fin.close();
			fin.open("pri_key.txt", ios::binary | ios::out);
			fin << "-----BEGIN PRIVATE KEY-----\n";
			fin << "q : " << q << endl;
			fin << "p : " << p << endl;
			fin << "a : " << a << endl;
			fin << "-----END PRIVATE KEY-----\n";
			fin.close();

			cout << endl << "the public key has writen into pub.txt,the private key is in pri.txt" << endl;
			cout << "press enter to continue" << endl;
			system("pause>nul");
		}
		else if (mod[0] == 's') {
			cout << "Plz input the filename to encrypt\n>>";
			cin >> filename;
			fin.open(filename, ios::binary | ios::in);
			if (!fin.is_open())
			{
				cout << "Can't open the file!" << endl;
				fin.close();
				break;
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
			stringstream ss;
			string signature = ez_sha_1(msg);//160bit
			//cout << signature << endl;
			//rsa
			cout << "Plz input the b : \n>>";
			cin >> b;
			cout << "Plz input the n : \n>>";
			cin >> n;
			ZZ temp;
			temp = 0;
			unsigned x = 0;
			//plaintext
			while (x < msg.length()) {
				if (msg[x] == ' '){
					x++;
					continue;
				}
				temp = 0;
				while (x < msg.length() && msg[x] != ' ') {
					temp = (temp * 256 + msg[x]) % n;
					x++;
				}
				ss << square_multi(temp, b, n) << "|";
			}
			ss << "hash:";
			//signature
			x = 0;
			temp = 0;
			while (x < signature.length()) {
				temp = (temp * 256 + signature[x]) % n;
				x++;
			}
			ss << square_multi(temp, b, n);
			msg = ss.str();
			//
			cout << "Writen into rsa_pkcs.txt" << endl;
			fstream fout;
			fout.open("rsa_pkcs.txt", ios::binary | ios::out);
			fout << msg;
			fout.close();
			cout << "Done." << endl;
		}
		else if (mod[0] == 'v') {
			string filename;
			cout << "Plz input the q : \n>>";
			cin >> q;
			cout << "Plz input the p : \n>>";
			cin >> p;
			cout << "Plz input the a : \n>>";
			cin >> a;
			cout << "Plz input the filename to decrypt: \n>>";
			cin >> filename;
			fstream fin;
			fin.open(filename, ios::in | ios::binary);
			if (!fin.is_open()) {
				fin.close();
				cout << "can't open the file!" << endl;
				break;
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
			n = p * q;
			ZZ temp;
			ZZ ans;
			ZZ cnt(1);

			stringstream tmp;
			string plaintext;
			unsigned char ch;
			unsigned x = 0;

			cout << "Plz wait for minutes, the string is generating." << endl;
			while (x < msg.length()) {
				if (msg[x] == '|') {
					++x;
					continue;
				}
				if (msg[x] == 'h')
					break;
				temp = 0;
				cnt = 1;
				ans = 0;
				tmp.str("");
				ch = 0;
				while (x < msg.length() && msg[x] != '|') {
					temp = (temp * 10 + msg[x] - '0');
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
				plaintext += ' ';
			}
			string hash = msg.substr(x + 5);
			x = 0;
			temp = 0;
			while (x < hash.length()) {
				temp = temp * 10 + hash[x] - '0';
				x++;
			}
			ans = square_multi(temp, a, n);
			hash = "";
			cnt = 1;
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
				hash += ch;
				ans %= cnt;
				cnt /= 256;
			}
			//cout << plaintext << endl;
			if (hash == ez_sha_1(plaintext.substr(0,plaintext.length()-1))) {
				//space is the final cahracter
				cout << "¡Ì" << endl;
				cout << "accepted" << endl;
				cout << "The plaintext is : " << plaintext << endl;
				continue;
			}
			else
			{
				cout << "The plaintext had been changed!!!" << endl;
				continue;
			}
		}
		else {
			continue;
		}
	}
}



string ez_sha_1(string str)
{
	/*PAD*/
	string ret = "";
	int pad = _SHA_1_PAD(str);
	if (pad == -1) {
		cout << "wrong range!" << endl;
		return "";
	}
	/*pre treat*/
	uint32_t str_pos = 0;
	string pre_treat;
	while (str_pos < str.length()) {
		pre_treat += _SHA_1_512bit_pre_treat(str.substr(str_pos, 64));
		str_pos += 64;
	}
	/*rolling*/
	/*initial*/
	string my_H[5];// 0-a 1-b 2-c 3-d 4-e
	for (int x = 0; x < 5; ++x) {
		my_H[x] = H0[x];
	}
	str_pos = 0;
	/*roll*/

	while (str_pos < pre_treat.length()) {
		one_512_circle(my_H, pre_treat.substr(str_pos, 80 * 4), 'n');
		str_pos += 80 * 4;
	}
	ret.clear();
	for (int x = 0; x < 5; ++x) {
		ret += my_H[x];
	}
	//cout << ret << endl;//here is the answer
	return ret;
}
