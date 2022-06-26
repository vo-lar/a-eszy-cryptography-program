/*main proc*/
#include "../header/Crypt.h"
#include <iostream>
#include <string>
using namespace std;


int main(void) 
{
	menu();
	return 0;
}



void menu() 
{
	string str;
	int mod;
	while (1) {
		str = "";
		mod = -2;
		cout << "Plz input the encrypt or decrypt mod: " << endl;
		cout << "supported mod:					"		<< endl;
		cout << "	AES                 --basic AES	"	<< endl;
		cout << "	AES-IN-CBC          --AES/CBC/PKCS5"<< endl;
		cout << "	SHA-1               --basic SHA-1"	<< endl;
		cout << "	RSA                 --RSA		"	<< endl;
		cout << "	RSA-PKCS            --RSA_PKCS	"	<< endl;
		cout << "	EZ-CA               --an eazy CA" << endl;
		cout << "	EZ-FES              --an easy file encryption system" << endl;
		cout << "	QUIT                --exit		"	<< endl;
		cout << "input cls or clear to clean the screen" << endl;
		//cout << "Finished mod:					"		<< endl;
		//cout << "	SHA-1               --basic SHA-1" << endl;
		cout << ">>";
		cin >> str;
		upper(str);
		//select mod
		if (str == "CLEAR" || str == "CLS") {
			system("cls");
			continue;
		}
		if (str == "AES")
			mod = AES;
		else if (str == "AES-IN-CBC")
			mod = AES_IN_CBC;
		else if (str == "SHA-1")
			mod = SHA_1;
		else if (str == "RSA")
			mod = RSA;
		else if (str == "RSA-PKCS")
			mod = RSA_PKCS;
		else if (str == "EZ-CA")
			mod = EZ_CA;
		else if (str == "EZ-FES")
			mod = EZ_FES;
		else if (str == "QUIT")
			mod = EXIT;
		if (mod == EXIT) {
			cout << "EXIT" << endl;
			break;
		}
		else if (mod > 0) {
			cout << "The mod is " << str << endl;
			select_MOD(mod);
		}
		else {
			cout << "wrong mod!" << endl;
		}
	}
}

void select_MOD(int choice) {
	string str;
	switch (choice) {
		case AES:
			cout << "encrypt / decrypt\n>>";
			cin >> str;
			lower(str);
			if (str[0] == 'e' || str[0] == 'd') {
				_AES_128(str);
			}
			else
				cout << "Wrong AES_mod!" << endl;
			break;
		case AES_IN_CBC:
			_AES_in_CBC();
			break;
		case SHA_1:
			_SHA_1();
			break;
		case RSA:
			_RSA();
			break;
		case RSA_PKCS:
			_RSA_PKCS();
			break;
		case EZ_CA:
			_EZ_CA("");
			break;
		case EZ_FES:
			_EZ_FES();
			break;
		default:
			break;
	}
}
