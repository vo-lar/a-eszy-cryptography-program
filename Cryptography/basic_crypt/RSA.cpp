/*RSA basic implementation*/
/*Need to achieve with NTL lib, http://www.shoup.net/ntl */

#include "../header/Crypt.h"
#include "../header/Crypt_RSA.h"
#include <fstream>
#include <string>
#include <Windows.h>
/*generate and en/de*/

void _RSA()
{
	string mod;
	uint16_t len = 0;
	while (1) {//one loop
		cout << "Plz choose the mod(encrypt or decrypt or generate_key), prese quit to exit \n>>";
		mod.clear();
		cin >> mod;
		lower(mod);
		ZZ p, q, a, n, b, phi_n;
		string msg;
		ZZ message;
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
			fin.open("pub.txt", ios::binary | ios::out);
			fin << "-----BEGIN PUBLIC KEY-----\n";
			fin << "n : " << n << endl;
			fin << "b : " << b << endl;
			fin << "-----END PUBLIC KEY-----\n";
			fin.close();
			fin.open("pri.txt", ios::binary | ios::out);
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
		else if (mod[0] == 'e') {
			cout << "Plz input the message : \n>>";
			while (cin.get() != '\n');
			getline(cin, msg);
			cout << "Plz input the b : \n>>";
			cin >> b;
			cout << "Plz input the n : \n>>";
			cin >> n;
			cout << "We make word->block,divided with \" | \"" << endl;
			ZZ temp;
			fstream fin;
			stringstream ss;
			for (unsigned x = 0; x < msg.length(); ++x) {
				temp = 0;
				while (x < msg.length() && msg[x] != ' ') {
					temp = (temp * 256 + msg[x]) % n;
					x++;
				}
				ss << square_multi(temp, b, n) << "|";
			}
			fin.open("rsa_encrypt.txt", ios::binary | ios::out);
			fin << ss.str();
			cout << ss.str().substr(0, ss.str().length() < 200 ? ss.str().length() : 200);
			if (ss.str().length() >= 200)
				cout << "..." << endl;
			fin.close();
			cout << endl;
		}
		else if (mod[0] == 'd') {
			string filename;
			cout << "Plz input the q : \n>>";
			cin >> q;
			cout << "Plz input the p : \n>>";
			cin >> p;
			cout << "Plz input the a : \n>>";
			cin >> a;
			cout << "We make block->word,divided with space " << endl;
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
			unsigned char ch;
			unsigned x = 0;
			char ss[100] = {'\0'};
			int i = 0;
			while(x < msg.length()) {
				if (msg[x] == '|') {
					++x;
					continue;
				}
				temp = 0;
				cnt = 1;
				ans = 0;
				i = 0;
				fill(ss, ss + 100, '\0');
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
					tmp << (ans / cnt) ;
					ch = 0;
					for (auto x : tmp.str()) {
						ch = ch * 10 + x - '0';
					}
					ss[i++] = ch;
					ans %= cnt;
					cnt /= 256;
				}
				ss[i++] = ' ';
				cout << ss;
			}
			cout << endl;
		}
		else {
			continue;
		}
	}
}



bool Miller_Rabin(ZZ n)
{
	ZZ k;
	ZZ m = n - 1;
	ZZ b;
	k = 0;
	while ((m & 1) != 1) {
		k++;
		m /= 2;
	}
	for (int i = 0; i < 500; i++) {
		ZZ a;
		a = RandomLen_ZZ(10 + i);
		//b = PowerMod(a, m, n);
		b = square_multi(a, m, n);
		if (b % n == 1)
			continue;
		bool flag = 0;
		for (ZZ i(0); i < k; ++i) {
			if ((b + n) % n ==  n - 1) {
				flag = 1;
				break;
			}
			else
				b = b * b % n;
		}
		if (flag)
			continue;
		else
			return false;
	}
	return true;
}

ZZ square_multi(ZZ a, ZZ b, ZZ n)
{
	ZZ MSB(1);
	ZZ temp(b);
	while (temp != 1) {
		MSB <<= 1;
		temp >>= 1;
	}
	
	stringstream ss;
	while (MSB != 0)
	{
		ss << !((MSB & b) == 0);
		MSB >>= 1;
	}
	//cout << ss.str() << endl << endl;
	ZZ ret(1);
	for (unsigned i = 0; i < ss.str().length(); ++i)
	{
		ret = ret * ret % n;
		if ((ss.str()[i] - '0'))
			ret = ret * a % n;
	}
	return ret;
}
