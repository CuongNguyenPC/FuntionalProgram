// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::wcout;
using std::wcin;
using std::cin;
using std::getline; 
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;
using std::wstring;
#include <cstdlib>
using std::exit;

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "cryptopp/des.h"
using CryptoPP::DES_EDE3;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;
using CryptoPP::byte;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

// conert string
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

//setting 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#else
#endif

string wstring_to_string (const std::wstring& str);
wstring string_to_wstring (const std::string& str);

int main(int argc, char* argv[])
{
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif
	AutoSeededRandomPool prng;

	SecByteBlock key(DES_EDE3::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	byte iv[DES_EDE3::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string plain = "CBC Mode Test";
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "iv: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		wstring wplain;
		string plain;
		wcout << "enter plain text you want to cipher: "<<endl;
		getline(wcin,wplain);

		wcout << "plain text: " << wplain << endl;
		plain = wstring_to_string(wplain);

		CBC_Mode< DES_EDE3 >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "cipher text: " << string_to_wstring(encoded) << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< DES_EDE3 >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		wcout << "recovered text: " << string_to_wstring(recovered) << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}

/* convert string to wstring */
wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t>> tostring;
    return tostring.to_bytes(str);
}
