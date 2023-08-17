// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "cryptopp/osrng.h" // generate random number
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::wcin;
using std::wcout;
using std::cerr;
using std::endl;
using std::getline;

#include <string>
using std::string;
using std::wstring;

#include <cstdlib>
using std::exit;
using CryptoPP::byte; // byte of cryptopp

#include "cryptopp/cryptlib.h"
using CryptoPP::Exception;

#include "cryptopp/hex.h" 
using CryptoPP::HexEncoder; // string to hex
using CryptoPP::HexDecoder; // hex to string

#include "cryptopp/base64.h" 
using CryptoPP::Base64Encoder; // string to base64
using CryptoPP::Base64Decoder; // base64 to string

#include "cryptopp/filters.h" // string filters
using CryptoPP::StringSink; // ouput string 
using CryptoPP::StringSource; //input string
using CryptoPP::StreamTransformationFilter; // string transformation

#include "cryptopp/files.h"
using CryptoPP::FileSource; // loade frome file 
using CryptoPP::FileSink;   // save to file

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::OFB_Mode;
using CryptoPP::CFB_Mode;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;

#include "cryptopp/xts.h"
using CryptoPP::XTS;

#include "cryptopp/secblock.h" // cryptopp byte (distinguish with c++ byte)
using CryptoPP::SecByteBlock; 

// Convert unicode
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#elif _APPLE_
#include <TargetConditionals.h>
#endif

// Functions
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);

int main(int argc, char* argv[])
{
	#ifdef __linux__
	setlocale(LC_ALL,"");
	#elif __APPLE__
    	#if TARGET_OS_MAC
        setlocale(LC_ALL,"");
		#else
		#endif
	#elif _WIN32
	_setmode(_fileno(stdin), _O_U16TEXT);
 	_setmode(_fileno(stdout), _O_U16TEXT);
	#else
	#endif
    
	AutoSeededRandomPool prng; 
	SecByteBlock key(AES::DEFAULT_KEYLENGTH); // 8 bytes
	prng.GenerateBlock(key, key.size());  // generate key

	byte iv[AES::BLOCKSIZE];   // inital vector 8 bytes 
	prng.GenerateBlock(iv, sizeof(iv));  // generate iv

	string plain; 
	wstring wplain;
	// input from files FileScource - StringSink
	wcout << "please enter name of input file (defaut text.txt)" <<endl;
    FileSource("text.txt",true, new StringSink(plain)); // read string from file
	//getline(wcin, wplain);   // input wstring
	//plain= wstring_to_string(wplain);
	string cipher, encoded, recovered; // 

	/*********************************\
	\*********************************/

    // cout << "key length: " << DES::DEFAULT_KEYLENGTH << endl;
    // cout << "block size: " << DES::BLOCKSIZE << endl;

	// Pretty print key in hex format
	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	wcout << "key: " << string_to_wstring(encoded) << endl;

	// Pretty print iv in hex format
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
		wcout << "plain text: " << string_to_wstring(plain)<< endl;

		OFB_Mode< AES >::Encryption e;
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

	// Pretty print ciphertext
	encoded.clear();
	StringSource(cipher, true,
		new Base64Encoder(
			new StringSink(encoded)
		) // Base64Encoder
	); // StringSource
	//wcout << "cipher text: " << string_to_wstring(encoded) << endl;
    // save ciphertext to file
	StringSource(encoded, true, new FileSink("cipher.txt")); //save file
	/*********************************\
	\*********************************/
	// Decryption: load from cipher, decrypt, display in screen and save to file "recovertext.txt"
	string fcipher,rcipher;
	FileSource("cipher.txt", true, new StringSink(fcipher));
	wcout << "cipher text: " << string_to_wstring(fcipher) << endl;
	StringSource(fcipher, true, new Base64Decoder( new StringSink(rcipher)));
	
	try {
	
		OFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		// load cipher text
		StringSource s(rcipher, true, 
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
std::wcout << "whould you like to exit?";
wcin.ignore();
std::wcin.get();
	return 0;
}

// Convert functions
/* convert string to wstring */

wstring string_to_wstring (const std::string& str)
{
    wstring_convert<codecvt_utf8<wchar_t, 0x10ffff>, wchar_t> towstring;
    return towstring.from_bytes(str);
}

/* convert wstring to string */
string wstring_to_string (const std::wstring& str)
{
    wstring_convert<codecvt_utf8<wchar_t, 0x10ffff>, wchar_t> tostring;
    return tostring.to_bytes(str);
}

