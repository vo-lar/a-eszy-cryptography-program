/*a simple Cryptography Certificate*/
#include "../header/Crypt.h"
#include "../header/Crypt_doc.h"


void _EZ_FES()
{
	string mod;
	while (1) {
		cout << "You can input quit to exit or input continue to continue\n>>";
		cin >> mod;
		if (mod == "quit") {
			cout << "EXIT" << endl << endl;
			break;
		}
		cout << "------------------------------------------------------------" << endl;
		cout << "Now you are Receiver(Alice)" << endl;
		cout << "TA:\"Personal TA in Tongji,shanghai\"" << endl;
		//_CA_receiver_1st();
		cout << "press enter to continue" << endl;
		system("pause>nul");
		cout << "------------------------------------------------------------" << endl;
		cout << "Now you are Sender(Bob)" << endl;
		_CA_sender();
		cout << "press enter to continue" << endl;
		system("pause>nul");
		cout << "------------------------------------------------------------" << endl;
		cout << "Now you are Receiver(Alice) again" << endl;
		_CA_receiver_2nd();
		cout << "------------------------------------------------------------" << endl << endl;
	}
}
