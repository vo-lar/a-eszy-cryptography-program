/*2053046 ÕÅè÷¿µ IS*/
#include <iostream>
#include <string>

/*AES(CBC) ALGORITHM*/
#include "Crypt_AES.h"
/*rsa */
#include "Crypt_RSA.h"
using namespace std;
/*definition*/
#define INF 0x3f3f3f3f
/*const*/
const int AES = 1;
const int AES_IN_CBC = 2;
const int SHA_1 = 3;
const int RSA = 4;
const int RSA_PKCS = 5;
const int EZ_CA = 6;
const int EZ_FES = 7;
const int EXIT = -1;

/*func*/
//main
void select_MOD(int choice);
void menu();

/*tools*/
void upper(string& str);
void lower(string& str);
uint32_t calc4(string str);
uint32_t calc8(string str);
string _8calc(uint64_t t);
string ROTL_t(string str, int t);




/*SHA-1*/

//*const param
const uint64_t MAX_LENGTH = int64_t(pow(2, 61));
const uint32_t MOD = uint32_t(pow(2, 32) - 1);
const string H0[5]
{
	"67452301",
	"efcdab89",
	"98badcfe",
	"10325476",
	"c3d2e1f0"
};
//*function
void _SHA_1();
void identify(string str);
int _SHA_1_PAD(string& str);
string _SHA_1_512bit_pre_treat(string str);
void one_512_circle(string my_H[], string pre, char choice);
uint64_t ft(string b, string c, string d, int t);
uint64_t Kt(int t);

/*easy ca*/
void _EZ_CA(string doc = "");
string ez_sha_1(string str);

/*doc en system*/
void _EZ_FES();