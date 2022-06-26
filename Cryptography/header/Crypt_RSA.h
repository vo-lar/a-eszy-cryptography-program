#pragma once
#include <iostream>
#include <string>
#include <iomanip>
#include <NTL/zz.h>
#include <sstream>
using namespace std;

/*NTL*/
using namespace NTL;
#pragma comment(lib,"NTL.lib")

/*rsa*/
void _RSA();
bool Miller_Rabin(ZZ n);
ZZ square_multi(ZZ a, ZZ b, ZZ n);

/*rsa pkcs*/
void _RSA_PKCS();
string ez_sha_1(string str);
