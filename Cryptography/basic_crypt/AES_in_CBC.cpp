/*2053046 ÕÅè÷¿µ IS*/
/*AES in CBC*/
#include "../header/Crypt.h"
#include "../header/Crypt_AES.h"
#include <fstream>
#include <Windows.h>
#include <random>
#include <sstream>
using namespace std;

template <size_t T1, size_t T2>
void print_box(uint8_t(&box)[T1][T2])
{
	uint8_t i, j;
	for (i = 0; i < T1; ++i) {
		for (j = 0; j < T2; ++j) {
			cout << setbase(16) << setw(2) << setfill('0') << uint16_t(box[i][j]) << " ";
		}
		cout << endl;
	}
	cout << endl;
}


/* */
void _AES_in_CBC(string choice,string outfile) {
	string mod;
	string filename;
	string input;
	string output;
	uint8_t ch = 0;
	stringstream ss;
	while (true) {
		mod.clear();
		filename.clear();
		input.clear();
		output.clear();
		ss.str("");
		ch = 0;
		if (choice == "") {
			cout << "encrypt/decrypt\n>>";
			cin >> mod;
		}
		else
			mod = choice;
		lower(mod);
		if (mod[0] != 'e' && mod[0] != 'd')
		{
			cout << "Wrong mod!\n";
			continue;
		}
		cout << "Plz input the pre-AES filename,ensure the file is in the same dir as exe\n>>";
		cin >> filename;
		fstream fin;
		fin.open(filename, ios::_Nocreate | ios::binary | ios::in);
		/*read*/
		if (!fin.is_open()) {
			cout << "The file isn't exist!!! Plz input again\n";
			fin.close();
			continue;
		}
		else {
			while ((fin.get()) != EOF)
			{
				fin.seekg(-1, ios::cur);
				ch = fin.get();
				input += uint8_t((((ch / 16) < 10) ? (ch / 16) + '0' : (ch / 16) - 10 + 'a'));
				input += uint8_t((((ch % 16) < 10) ? (ch % 16) + '0' : (ch % 16) - 10 + 'a'));
			}
			fin.close();
		}
		/*write*/
		string IV;
		string key;
		string temp;
		string s;
		uint32_t cnt = 0;
		fstream fout;
		filename.clear();
		if (outfile == "") {
			cout << "Plz input the output file\n>>";
			cin >> filename;
		}
		else
			filename = outfile;
		fout.open(filename, ios::binary | ios::out);
		
		if (!fout.is_open()) {
			cout << "wrong!" << endl;
			break;
		}
		if (mod[0] == 'e') {
			int len = 0;
			/*fill*/
			cout << "the string is padded with \"0x\",x=[1..8]" << endl;
			len = input.length() % 32 / 2;

			for (int i = 0; i < 16 - len; ++i) {
				ss << setw(2) << setfill('0') << setbase(16) << 16 - len;
			}
			input += ss.str();

			srand((unsigned int)(time(0)));
			IV = initial();
			key = initial();
			cout << "The AES_IV  to encrypt is : " << IV << endl;
			cout << "The AES_key to decrypt is : " << re_key(key) << endl;

			/*store key*/
			fstream key_IV;
			key_IV.open("aes_cbc_key.enc", ios::out | ios::binary | ios::trunc);
			cout << "Writen into aes_cbc_key.enc.";
			key_IV << "-------------------------key-------------------------\n" << re_key(key) << "\n" << "-------------------------IV -------------------------\n" << IV << "\n" << "-----------------------------------------------------";
			key_IV.close();
			cout << "Done.\n" << endl;
			temp = IV;
			/*en*/
			cnt = 0;
			while (cnt < input.length()) {
				s = "";
				/*XOR*/
				for (int i = 0; i < 32; ++i) {
					ch = (input[i + cnt] <= '9' ? input[i + cnt] - '0' : input[i + cnt] - 'a' + 0x0a) ^ (temp[i] <= '9' ? temp[i] - '0' : temp[i] - 'a' + 0x0a);
					s += (ch <= 9 ? ch + '0' : ch - 0x0a + 'a');
				}
				/*AES*/
				temp = simple_AES(s, key, 'e');
				output += temp;
				cnt += 32;
			}
			/*CHANGE*/
			cnt = 0;
			ss.str("");

			while (cnt < output.length()) {
				ss << uint8_t((output[cnt] <= '9' ? output[cnt] - '0' : output[cnt] - 'a' + 0x0a) * 16 + (output[cnt + 1] <= '9' ? output[cnt + 1] - '0' : output[cnt + 1] - 'a' + 0x0a));
				cnt += 2;
			}
			fout << ss.str();
			fout.close();
		}
		else if (mod[0] == 'd') {
			cout << "Plz input the IV to decrypt\n>>";
			cin >> IV;
			cout << "Plz input the key to decrypt\n>>";
			cin >> key;
			temp = IV;
			/*XOR*/
			cnt = 0;
			output = "";
			while (cnt < input.length()) {
				s.clear();
				s = simple_AES(input.substr(cnt, min(32, input.length() - cnt)), key, 'd');
				for (int i = 0; i < 32; ++i) {
					ch = (s[i] <= '9' ? s[i] - '0' : s[i] - 'a' + 0x0a) ^ (temp[i] <= '9' ? temp[i] - '0' : temp[i] - 'a' + 0x0a);
					ch = (ch <= 9 ? ch + '0' : ch - 0x0a + 'a');
					s[i] = ch;
				}
				temp = input.substr(cnt, 32);
				output += s;
				cnt += 32;
			}
			/*CHANGE*/
			cnt = 0;
			ss.str("");
			while (cnt < output.length()) {
				ch = uint8_t((output[cnt] <= '9' ? output[cnt] - '0' : output[cnt] - 'a' + 0x0a) * 16 + (output[cnt + 1] <= '9' ? output[cnt + 1] - '0' : output[cnt + 1] - 'a' + 0x0a));
				ss << ch;
				cnt += 2;
			}
			fout << ss.str().substr(0, ss.str().length()-ch);
			fout.close();
			
		}
		else
			break;
		if (choice != "")
			break;
	}
}

string initial()
{
	/*genarate 32 charactor, 32 * 4 = 128*/
	string ret;
	uint8_t num;
	for (int i = 0; i < 32; ++i) {
		num = rand() % 16;
		if (num <= 9)
			num += '0';
		else
			num += ('a' - 10);
		ret += num;
	}
	return ret;
}

string simple_AES(string text_in, string key_in, uint8_t mod)
{
	uint8_t temp = 0;
	uint8_t P_BOX[4][4] = { 0 };
	uint8_t KEY_BOX[4][44] = { 0 };//1+10 * 4
	int8_t i, j;
	string text, key;
	stringstream ss;
	for (i = 0; i < 16; i++) {
		temp = (text_in[2 * i + 1] <= '9' ? text_in[2 * i + 1] - '0' : text_in[2 * i + 1] - 'a' + 10) + (text_in[2 * i] <= '9' ? text_in[2 * i] - '0' : text_in[2 * i] - 'a' + 10) * 16;
		text += (uint8_t(temp));
	}
	for (i = 0; i < 16; i++) {
		temp = (key_in[2 * i + 1] <= '9' ? key_in[2 * i + 1] - '0' : key_in[2 * i + 1] - 'a' + 10) + (key_in[2 * i] <= '9' ? key_in[2 * i] - '0' : key_in[2 * i] - 'a' + 10) * 16;
		key += (uint8_t(temp));
	}
	if (mod == 'e') {
		initial(P_BOX, text, 1);
		initial(KEY_BOX, key, mod == 'e');
		key_extend(KEY_BOX);
		AddRoundKey(P_BOX, KEY_BOX);
		for (i = 1; i <= 10; ++i) {
			Sub_Bytes(P_BOX);
			Shift_Rows(P_BOX);
			if (i != 10) {
				for (j = 0; j < 4; ++j) {
					MixColumn(P_BOX, j);
				}
			}
			AddRoundKey(P_BOX, KEY_BOX, i);
		}
		for (i = 0; i < 4; ++i) {
			for (j = 0; j < 4; ++j) {
				//cout << setbase(16) << setw(2) << setfill('0') << uint16_t(P_BOX[j][i]);
				ss << setbase(16) << setw(2) << setfill('0') << uint16_t(P_BOX[j][i]);
			}
		}
		/*end of en */
	}
	else if (mod == 'd') {
		initial(P_BOX, text, 1);
		initial(KEY_BOX, key, mod == 'e');
		de_key_extend(KEY_BOX);
		for (i = 10; i > 0; --i) {
			AddRoundKey(P_BOX, KEY_BOX, i);
			if (i != 10) {
				for (j = 0; j < 4; ++j) {
					De_MixColumn(P_BOX, j);
				}
			}
			De_Shift_Rows(P_BOX);
			De_Sub_Bytes(P_BOX);
		}
		AddRoundKey(P_BOX, KEY_BOX);
		for (i = 0; i < 4; ++i) {
			for (j = 0; j < 4; ++j) {
				//cout << setbase(16) << setw(2) << setfill('0') << uint16_t(P_BOX[j][i]);
				ss << setbase(16) << setw(2) << setfill('0') << uint16_t(P_BOX[j][i]);
			}
		}
		/*end of de*/
	}
	return ss.str();
}

string re_key(string key_in)
{
	uint8_t temp = 0;
	uint8_t i, j;
	uint8_t KEY_BOX[4][44] = { 0 };//1+10 * 4
	string key;
	stringstream ss;
	for (i = 0; i < 16; i++) {
		temp = (key_in[2 * i + 1] <= '9' ? key_in[2 * i + 1] - '0' : key_in[2 * i + 1] - 'a' + 10) + (key_in[2 * i] <= '9' ? key_in[2 * i] - '0' : key_in[2 * i] - 'a' + 10) * 16;
		key += (uint8_t(temp));
	}
	initial(KEY_BOX, key, 1);
	key_extend(KEY_BOX);
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			ss << setbase(16) << setw(2) << setfill('0') << uint16_t(KEY_BOX[j][i+40]);
		}
	}
	return ss.str();
}