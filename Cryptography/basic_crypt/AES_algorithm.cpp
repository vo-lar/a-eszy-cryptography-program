/*2053046 ÕÅè÷¿µ IS*/
/*AES algorithm*/
/*len(key) = 128*/

#include "../header/Crypt.h"
#include "../header/Crypt_AES.h"

/*main*/
void _AES_128(string mod)
{
	string text;
	string key;
	string input;
	uint8_t temp = 0;
	uint8_t P_BOX[4][4] = { 0 };
	uint8_t KEY_BOX[4][44] = { 0 };//1+10 * 4
	uint8_t i, j; 
	
	while (1) {
		cout << "Plz make sure the length of text and key equal to 32, press -1 to exit\ntext>>";
		/*text*/
		text.clear();
		key.clear();
		input.clear();
		memset(P_BOX, 0, sizeof(P_BOX));
		memset(KEY_BOX, 0, sizeof(KEY_BOX));
		cin >> input;
		if (input[0] == '-' && input[1] == '1')
			break;
		for (i = 0; i < 16; i++) {
			input[2 * i + 1] = (input[2 * i + 1] >= 'a' ? input[2 * i + 1] - 'a' + 'A' : input[2 * i + 1]);
			input[2 * i] = (input[2 * i] >= 'a' ? input[2 * i] - 'a' + 'A' : input[2 * i]);
			temp = (input[2 * i + 1] <= '9' ? input[2 * i + 1] - '0' : input[2 * i + 1] - 'A' + 10) + (input[2 * i] <= '9' ? input[2 * i] - '0' : input[2 * i] - 'A' + 10) * 16;
			text += (uint8_t(temp));
		}
		if (text.length() != 16) {
			cout << "Wrong Length of plaintext!!!Plz input again!\n";
			continue;
		}
		/*key*/
		input.clear();
		cout << "key>>";
		cin >> input;
		if (input[0] == '-' && input[1] == '1')
			break;
		for (i = 0; i < 16; i++) {
			input[2 * i + 1] = (input[2 * i + 1] >= 'a' ? input[2 * i + 1] - 'a' + 'A' : input[2 * i + 1]);
			input[2 * i] = (input[2 * i] >= 'a' ? input[2 * i] - 'a' + 'A' : input[2 * i]);
			temp = (input[2 * i + 1] <= '9' ? input[2 * i + 1] - '0' : input[2 * i + 1] - 'A' + 10) + (input[2 * i] <= '9' ? input[2 * i] - '0' : input[2 * i] - 'A' + 10) * 16;
			key += (uint8_t(temp));
		}
		if (key.length() != 16) {
			cout << "Wrong Length of the key!!!Plz input again!\n";
			continue;
		}
		/*store*/
		initial(P_BOX, text,1);
		/*store*/
		initial(KEY_BOX, key, mod[0] == 'e');
		if (mod[0] == 'e') {
			/*encrypt*/
			key_extend(KEY_BOX);
			/*initial round*/
			AddRoundKey(P_BOX, KEY_BOX);
			/*10 round*/
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
			cout << "AES value(as a hex types string)" << endl;
			for (i = 0; i < 4; ++i) {
				for (j = 0; j < 4; ++j) {
					cout << setbase(16) << setw(2) << setfill('0') << uint16_t(P_BOX[j][i]);
				}
			}
			cout << endl << endl;
			/*end of en*/
		}
		else if (mod[0] == 'd') {
			/*decrypt*/
			de_key_extend(KEY_BOX);
			
			/*10 round*/
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
			/*final round*/
			AddRoundKey(P_BOX, KEY_BOX);
			cout << "AES value(as a hex types string)" << endl;
			for (i = 0; i < 4; ++i) {
				for (j = 0; j < 4; ++j) {
					cout << setbase(16) << setw(2) << setfill('0') << uint16_t(P_BOX[j][i]);
				}
			}
			cout << endl << endl;
			/*end of de*/
		}
	}
}


/*General*/
template <size_t T1, size_t T2>
void initial(uint8_t (&box)[T1][T2], string text,bool true_as_en)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i) {
		if (true_as_en) {
			for (j = 0; j < 4; ++j) {
				box[j][i] = text[j + 4 * i];
			}
		}
		else {
			for (j = 0; j < 4; ++j) {
				box[j][T2 - 4 + i] = text[j + 4 * i];
			}
		}
	}
}

template <size_t T1, size_t T2>
void print_box(uint8_t (&box)[T1][T2])
{
	uint8_t i, j;
	for (i = 0; i < T1; ++i) {
		for (j = 0; j < T2; ++j) {
			cout <<setbase(16)<<setw(2)<<setfill('0')<< uint16_t(box[i][j]) << " ";
		}
		cout << endl;
	}
	cout << endl;
}

uint8_t FieldMult(uint8_t x)
{
	bool t = 0x80 & x;
	uint8_t y = x << 1;
	if (t == 1)
		return y ^ 0b00011011;
	else
		return y;
}

/*encrypt*/
template <size_t T1, size_t T2>
void key_extend(uint8_t(&box)[T1][T2])
{
	uint8_t i, j;
	uint8_t word[4] = {0};
	for (i = 4; i < T2; ++i) {
		if (i % 4 != 0) {
			for (j = 0; j < T1; ++j) {
				box[j][i] = box[j][i - 4] ^ box[j][i - 1];
			}
		}
		else {
			for (j = 0; j < T1; ++j) {
				word[j] = box[(j + 1) % T1][i - 1];
			}//shift
			for (j = 0; j < 4; ++j) {
				word[j] = S_BOX[word[j] / 16][word[j] % 16];
			}//S-BOX
			for (j = 0; j < T1; ++j) {
				box[j][i] = box[j][i - 4] ^ word[j] ^ K_EXTEND[j][i/4 - 1];
			}//XOR
		}
	}
}

void Sub_Bytes(uint8_t box[4][4])
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			box[i][j]= S_BOX[box[i][j] / 16][box[i][j] % 16];
		}
	}
}

void Shift_Rows(uint8_t box[4][4])
{
	uint8_t i, j;
	uint8_t shift[4] = { 0 };
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			shift[j] = box[i][j];
		}//fill
		for (j = 0; j < 4; ++j) {
			box[i][j] = shift[(i + j) % 4];
		}//fill
	}
}

void MixColumn(uint8_t BOX[4][4], int t)
{
	uint8_t i;
	uint8_t X[4] = { 0 };
	for (i = 0; i < 4; ++i) {
		X[i] = BOX[i][t];
	}
	BOX[0][t] = X[1] ^ X[2] ^ X[3];
	BOX[1][t] = X[0] ^ X[2] ^ X[3];
	BOX[2][t] = X[0] ^ X[1] ^ X[3];
	BOX[3][t] = X[0] ^ X[1] ^ X[2];
	for (i = 0; i < 4; ++i) {
		X[i] = FieldMult(X[i]);
	}
	BOX[0][t] = BOX[0][t] ^ X[0] ^ X[1];
	BOX[1][t] = BOX[1][t] ^ X[1] ^ X[2];
	BOX[2][t] = BOX[2][t] ^ X[2] ^ X[3];
	BOX[3][t] = BOX[3][t] ^ X[3] ^ X[0];
}

template <size_t T1, size_t T2>
void AddRoundKey(uint8_t P_BOX[4][4], uint8_t(&KEY_BOX)[T1][T2],int round)
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			P_BOX[j][i] = P_BOX[j][i] ^ KEY_BOX[j][i + 4 * round];
		}
	}
}

/*decrypt*/
template <size_t T1, size_t T2>
void de_key_extend(uint8_t(&box)[T1][T2])
{
	int8_t i, j;
	uint8_t word[4] = { 0 };
	for (i = T2 - 5; i >= 0; --i) {
		if (i % 4 != 0) {
			for (j = 0; j < T1; ++j) {
				box[j][i] = box[j][i + 4] ^ box[j][i + 3];
			}
		}
		else {
			for (j = 0; j < T1; ++j) {
				word[j] = box[(j + 1) % T1][i + 3];
			}//shift
			for (uint8_t j = 0; j < 4; ++j) {
				word[j] = S_BOX[word[j] / 16][word[j] % 16];
			}//S-BOX
			for (j = 0; j < T1; ++j) {
				box[j][i] = box[j][i + 4] ^ word[j] ^ K_EXTEND[j][i / 4];
			}//XOR
		}
	}
}

void De_MixColumn(uint8_t BOX[4][4], int t)
{
	uint8_t i;
	uint8_t X[4] = { 0 };
	for (i = 0; i < 4; ++i) {
		X[i] = BOX[i][t];
	}

	BOX[0][t] = X[1] ^ X[2] ^ X[3];
	BOX[1][t] = X[0] ^ X[2] ^ X[3];
	BOX[2][t] = X[0] ^ X[1] ^ X[3];
	BOX[3][t] = X[0] ^ X[1] ^ X[2];

	for (i = 0; i < 4; ++i) {
		X[i] = FieldMult(X[i]);
	}

	BOX[0][t] = BOX[0][t] ^ X[0] ^ X[1];
	BOX[1][t] = BOX[1][t] ^ X[1] ^ X[2];
	BOX[2][t] = BOX[2][t] ^ X[2] ^ X[3];
	BOX[3][t] = BOX[3][t] ^ X[3] ^ X[0];

	X[0] = FieldMult(X[0] ^ X[2]);
	X[1] = FieldMult(X[1] ^ X[3]);

	BOX[0][t] = BOX[0][t] ^ X[0];
	BOX[1][t] = BOX[1][t] ^ X[1];
	BOX[2][t] = BOX[2][t] ^ X[0];
	BOX[3][t] = BOX[3][t] ^ X[1];

	X[0] = FieldMult(X[0] ^ X[1]);

	BOX[0][t] = BOX[0][t] ^ X[0];
	BOX[1][t] = BOX[1][t] ^ X[0];
	BOX[2][t] = BOX[2][t] ^ X[0];
	BOX[3][t] = BOX[3][t] ^ X[0];
}

void De_Shift_Rows(uint8_t box[4][4])
{
	uint8_t i, j;
	uint8_t shift[4] = { 0 };
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			shift[j] = box[i][j];
		}//fill
		for (j = 0; j < 4; ++j) {
			box[i][j] = shift[((4 - i) + j) % 4];
		}//fill
	}
}

void De_Sub_Bytes(uint8_t box[4][4])
{
	uint8_t i, j;
	for (i = 0; i < 4; ++i) {
		for (j = 0; j < 4; ++j) {
			box[i][j] = DE_S_BOX[box[i][j] / 16][box[i][j] % 16];
		}
	}
}