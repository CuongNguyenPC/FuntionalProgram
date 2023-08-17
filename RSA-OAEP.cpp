// Sample.cpp
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/modarith.h>
using CryptoPP::ModularArithmetic;

#include <D:\ProjectNS\include\cryptopp\nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include "cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_PKCS1v15_Encryptor;
using CryptoPP::RSAES_PKCS1v15_Decryptor;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;



#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/SecBlock.h"
using CryptoPP::SecByteBlock;

// Generate public / secret key pairs
#include "cryptopp/cryptlib.h"
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::BufferedTransformation;
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/base64.h"
using CryptoPP::Base64Encoder;
using CryptoPP::Base64Decoder;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;
#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <string>
using std::string;
using std::wstring;

#include <exception>

using std::exception;

#include <iostream>
using std::cin;
using std::cout;
using std::cerr;
using std::wcin;
using std::wcout;
using std::endl;


#include <assert.h>

// Functions
void Load(const string& filename, BufferedTransformation& bt);
void LoadPrivateKey(const string& filename, PrivateKey& key);
void LoadPublicKey(const string& filename, PublicKey& key);
string integer_to_hex(const CryptoPP::Integer& t);
wstring integer_to_wstring(const CryptoPP::Integer& t);
string integer_to_string(const CryptoPP::Integer& t);


// convert string
#include <locale>
using std::wstring_convert;
#include <codecvt>
using std::codecvt_utf8;

//setting 
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#elif _APPLE_
#include <TargetConditionals.h>
#endif

string wstring_to_string (const std::wstring& str);
wstring string_to_wstring (const std::string& str);

int main(int argc, char* argv[])
{
    /*Set mode support Vietnamese*/
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
    try
    {
        ////////////////////////////////////////////////
        // Generate keys: module n = p.q, SK = (n, d), PK = (n, e), e.d = 1 mod phi(n)
        // Create a random private key
        AutoSeededRandomPool rng;
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize( rng, 3072 );
        // Create the public key
        RSA::PublicKey publicKey(privateKey);

        // Input message
        wstring wplain;
        string plain, cipher, recovered, encoded;
        wcout << "Input plain text here: ";
        getline(wcin,wplain);
        wcin.ignore();
        plain = wstring_to_string(wplain);
        wcout << "Plain text: " << wplain << endl;
        ////////////////////////////////////////////////
        // Encryption c = m^e, e is public key
        RSAES_OAEP_SHA_Encryptor e( publicKey );
        StringSource( plain, true,
            new PK_EncryptorFilter( rng, e,
                new StringSink( cipher )
            ) 
         ); // input: plain; encryption: e; output: cipher


       /* Pretty print private key */
        wstring hexSK, hexPK, hexmodul, hexprime1, hexprime2;
        Integer modul=privateKey.GetModulus();

        hexmodul = integer_to_wstring(privateKey.GetModulus());
        wcout << "modul n=p.q: " << hexmodul << endl;
        Integer prime1 = privateKey.GetPrime1();
        hexprime1 = integer_to_wstring(privateKey.GetPrime1());
        wcout << "primenumber p: " << hexprime1 << endl;
        Integer prime2 = privateKey.GetPrime2();
        hexprime2 = integer_to_wstring(privateKey.GetPrime2());
        wcout << "primenumber q: " << hexprime2 << endl;
        /* Secret exponent d; public exponent e */
        hexSK = integer_to_wstring(privateKey.GetPrivateExponent());
        wcout << "secret key d: " << hexSK << endl;
        hexPK = integer_to_wstring(privateKey.GetPublicExponent());
        wcout << "public key e: " << hexSK << endl;
        /* Check the keys */
        ModularArithmetic ma(modul); // mod n
        Integer ncheck= ma.Multiply(prime1, prime2);
        wcout << "p.q=n?: " << integer_to_wstring (ncheck) << endl;
        ////////////////////////////////////////////////
        ////////////////////////////////////////////////

        ////////////////////////////////////////////////
        // Decryption m = c^d mod n
        // input: cipher; output: recovered; decryption: d
        RSAES_OAEP_SHA_Decryptor d( privateKey ); // decryption with secret key
        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, d,
                new StringSink( recovered )
            ) // PK_DecryptorFilter
         ); // StringSource
        wcout << "Recovered text: " << string_to_wstring(recovered) << endl;
        assert( plain == recovered );
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

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