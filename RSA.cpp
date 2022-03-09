#include "include/cryptopp/rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "include/cryptopp/sha.h"
using CryptoPP::SHA512;

#include "include/cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;


#include "include/cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "include/cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "include/cryptopp/queue.h" // using for load functions 
using CryptoPP::ByteQueue;

#include "include/cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "include/cryptopp/cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;
using CryptoPP::BufferedTransformation; // using for load function

#include <string>
using std::string;
using std::wstring;

#include <exception>
using std::exception;

#include <iostream>
using std::wcout;
using std::wcin;
using std::cerr;
using std::endl;
#include <fstream>

/* Convert to hex */ 
#include "include/cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <assert.h>

/* Vietnamese support */
        
/* Set _setmode()*/ 
#ifdef _WIN32
#include <io.h> 
#include <fcntl.h>
#else
#endif

/* String convert */
#include <locale>
using std::wstring_convert;
#include <codecvt>
using  std::codecvt_utf8;

/* Integer convert */
#include <sstream>
using std::ostringstream;

/* Vietnames convert function def*/
wstring string_to_wstring (const std::string& str);
string wstring_to_string (const std::wstring& str);
wstring integer_to_wstring (const CryptoPP::Integer& t);

/*Load key from files (X.509 binary)*/
void LoadPrivateKey(const string& filename, RSA::PrivateKey& key);
void LoadPublicKey(const string& filename, RSA::PublicKey& key);
void Load(const string& filename, BufferedTransformation& bt);

AutoSeededRandomPool rng;

// RSA Function
string encryptRSA(RSA::PublicKey publicKey, string plain);
string decryptRSA(RSA::PrivateKey privateKey, string cipher);

// Input and output file
string ReadFromFile(string filename);
void WriteToFile(string filename, string data);
int main(int argc, char* argv[])
{
    try
    {	
        /*Set mode support Vietnamese*/
	    #ifdef __linux__
	    setlocale(LC_ALL,"");
	    #elif _WIN32
	    _setmode(_fileno(stdin), _O_U16TEXT);
 	    _setmode(_fileno(stdout), _O_U16TEXT);
	    #else
	    #endif
       
        // Generate keys
        //InvertibleRSAFunction parameters;
        //parameters.GenerateRandomWithKeySize(rng, 3072 );
        // Load key from files
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;
        LoadPublicKey ("rsa-public.key", publicKey);
        LoadPrivateKey ("rsa-private.key", privateKey);

        // RSA parameters n, p,q, e,d
        /*
        wcout << "RSA parameters:" << endl;
        wcout << "Public modulo n=" << integer_to_wstring(publicKey.GetModulus()) << endl;
        wcout << "Public key e=" << integer_to_wstring(publicKey.GetPublicExponent()) << endl;
        wcout << "Private prime number p=" << integer_to_wstring(privateKey.GetPrime1()) << endl;
        wcout << "Private prime number q=" << integer_to_wstring(privateKey.GetPrime2()) << endl;
        wcout << "Secret key d=" << integer_to_wstring(privateKey.GetPrivateExponent()) << endl;
        */

        string plain, cipher, recovered;


        // Người dùng chọn mã hoá hay giải mã tin nhắn
        wcout << "RSA Encryption/Decryption" << endl;
        wcout << "1. Encrypt" << endl << "2. Decrypt" << endl;
        int input1;
        wcin >> input1;
        // Mã hoá
        if(input1 == 1)
        {
            // Người dùng chọn input plaintext
            wcout << "1. Plaintext from screen" << endl << "2. Plaintext from file" << endl;
            int input2;
            wcin >> input2;
            if (input2 == 1)
            {
                wcout << "Input Plaintext: ";
                wstring wplain;
                fflush(stdin);
                getline(wcin,wplain);
                plain = wstring_to_string(wplain);
                cipher = encryptRSA(publicKey, plain);
                WriteToFile("ciphertext.txt", cipher);
            }
            else if (input2 == 2)
            {
                plain = ReadFromFile("plaintext.txt");
                wcout << "Plaintext: " << string_to_wstring(plain) << endl;
                cipher = encryptRSA(publicKey, plain);
                WriteToFile("ciphertext.txt", cipher);
            }
            else
            {
                wcout << "Invalid input";
                return 0;
            }
        }
        // Giải mã
        else if(input1 == 2)
        {
            wcout << "1. Ciphertext from screen" << endl << "2. Ciphertext from file" << endl;
            int input2;
            wcin >> input2;
            if (input2 == 1)
            {
                wcout << "Input ciphertext: ";
                wstring inputCipher;
                getline(wcin, inputCipher);
                recovered = decryptRSA(privateKey, wstring_to_string(inputCipher));
                wcout << "Recovered: " << string_to_wstring(recovered);
            }
            else if (input2 == 2)
            {
                string cipherFromfile = ReadFromFile("ciphertext.txt");
                wcout << "Ciphertext: " << string_to_wstring(cipherFromfile) << endl;
                recovered = decryptRSA(privateKey, cipherFromfile);
                wcout << "Recovered: " << string_to_wstring(recovered);
            }
            else
            {
                wcout << "Invalid input";
                return 0;
            }
        }
        else
        {
            wcout << "Invalid input";
            return 0;
        }
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}

/* Convert interger to wstring */
wstring integer_to_wstring (const CryptoPP::Integer& t)
{
    std::ostringstream oss;
    oss.str("");
    oss.clear();
    oss << t; // pumb t to oss
    std::string encoded(oss.str()); // to string 
    std::wstring_convert<codecvt_utf8<wchar_t>> towstring;
    return towstring.from_bytes(encoded); // string to wstring 
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


void LoadPrivateKey(const string& filename, RSA::PrivateKey& key)
{
	ByteQueue queue;
	Load(filename, queue);
	key.Load(queue);	
}

void LoadPublicKey(const string& filename, RSA::PublicKey& key)
{

	ByteQueue queue;
	Load(filename, queue);
	key.Load(queue);	
}

void Load(const string& filename, BufferedTransformation& bt)
{
	FileSource file(filename.c_str(), true /*pumpAll*/);
	file.TransferTo(bt);
	bt.MessageEnd();
}

// Encrypt function
string encryptRSA(RSA::PublicKey publicKey, string plain)
{
    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;
    string cipher;

    // Bắt đầu tính thời gian
	start_time = clock();
    RSAES_OAEP_SHA_Encryptor e( publicKey ); // RSAES_PKCS1v15_Decryptor

    StringSource( plain, true,
        new PK_EncryptorFilter( rng, e,
            new StringSink( cipher )
        ) // PK_EncryptorFilter
    ); // StringSource
    string encoded;
    encoded.clear();
    StringSource(cipher, true, 
    new HexEncoder(new StringSink(encoded)) );
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    wcout << "Ciphertext: " << string_to_wstring(encoded) << endl;
    
    wcout << "Execution time: " << exec_time << "ms" << endl;
    return cipher;
}

// Decrypt function
string decryptRSA(RSA::PrivateKey privateKey, string cipher)
{
    int stop_time = 0, start_time = 0;
	// Biến đo thời gian thực hiện (thập phân, milisecond)
	double exec_time = 0;
    
    string recovered;
    // Bắt đầu tính thời gian
	start_time = clock();

    RSAES_OAEP_SHA_Decryptor d(privateKey );
        StringSource( cipher, true,
            new PK_DecryptorFilter( rng, d,
                new StringSink(recovered )
            ) // PK_EncryptorFilter
        ); // StringSource
    stop_time = clock();
    exec_time = exec_time + (stop_time - start_time) / double(CLOCKS_PER_SEC)*1000;
    wcout << "Recover text:" << string_to_wstring(recovered) << endl;
    wcout << "Execution time: " << exec_time << "ms" << endl;
    return recovered;
}

// Read input from file
string ReadFromFile(string filename)
{
    string output;
    std::fstream my_file;
	my_file.open(filename, std::ios::in);
	/*if (!my_file) {
		output = "";
        return output;
	}
	else*/ 
    {
		char ch;
		while (1) {
			my_file >> ch;
			if (my_file.eof())
				break;
			output += ch;
		}
	}
	my_file.close();
    return output;
}

void WriteToFile(string filename, string data)
{
    std::ofstream myFile_Handler;
    // File Open
    myFile_Handler.open(filename, std::ios::trunc);

    // Write to the file
    myFile_Handler << data;

    // File Close
    myFile_Handler.close();
}