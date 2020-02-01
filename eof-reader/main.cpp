/*
	-----------------------------------------------------------------------------

	Jean-Pierre LESUEUR (@DarkCoderSc)
	jplesueur@phrozen.io

	License : MIT

	Read EOF (End Of File) Data from PE File.
	Based on my previous work : https://github.com/DarkCoderSc/peof-detector/blob/master/UntEOF.pas

	Compiled with : Visual Studio 2019 (Community)

	Notice :

	   	If you have any advices for improving the code or if you have any issues, feel free to contact me.	
		C++ is not yet my main language, always willing to learn ;-)

	-----------------------------------------------------------------------------

*/

#include <iostream>
#include <fstream>
#include "windows.h"
#include <iomanip>
#include <sstream>
#include "termcolor/termcolor.hpp"

using namespace std;

/*
	Log functions
*/
void log_error(const string &message) {
	cerr << " " << termcolor::bloodred << "x" << termcolor::reset << " " << message << endl;
}

void log_debug(const string &message) {
	cout << " " << "*" << " " << message << endl;
}

void log_success(const string &message) {
	cout << " " << termcolor::lime << "*" << termcolor::reset << " " << message << endl;
}

void log_warn(const string &message = "") {
	cout << " " << termcolor::yellow << "!" << termcolor::reset << " " << message << endl;
}

/*
	Dump memory data to console.
*/
void HexDumpBufferToConsole(PVOID pBuffer, __int64 ABufferSize) {
	cout << "| ------------------------------------------------|------------------|" << endl;
	cout << "| 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |                  |" << endl;
	cout << "| ------------------------------------------------|------------------|" << endl;

	for (int j = 0; j < ceil(ABufferSize / 16); j++) {
		char AsciiColumns[17];

		stringstream ARow;

		for (int i = 0; i < 16; i++) {
			unsigned char AChar = ((char*)pBuffer)[(j * 16) + i];

			if (!isprint(AChar)) {
				AChar = 46; // .
			}

			ARow << setfill('0') << setw(2) << hex << static_cast<unsigned int>(AChar) << " ";

			AsciiColumns[i] = AChar;
		}

		AsciiColumns[16] = 0; // Add null terminated character.

		cout << "| " << ARow.rdbuf() << "| " << AsciiColumns << " |" << endl;
	}

	cout << "| ------------------------------------------------|------------------|" << endl << endl;
}

/*
	Dump memory data to file.
*/
bool WriteBufferToFile(PVOID pBuffer, __int64 ABufferSize, wstring ADestFile, PDWORD AErrorCode) {
	SetLastError(0);

	HANDLE hFile = CreateFile(ADestFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		*AErrorCode = GetLastError();

		return false;
	}

	DWORD dwBytesWritten = 0;

	if (!WriteFile(hFile, pBuffer, ABufferSize, &dwBytesWritten, nullptr)) {
		*AErrorCode = GetLastError();

		CloseHandle(hFile);

		return false;
	}

	CloseHandle(hFile);

	return true;
}

/*
	Basic way to read file size from disk
*/
__int64 GetFileSize(wchar_t AFileName[MAX_PATH]) {
	LARGE_INTEGER AFileSize;

	AFileSize.LowPart = 0;
	AFileSize.HighPart = 0;
	
	ifstream ifile(AFileName);
	if (ifile) {		
		WIN32_FILE_ATTRIBUTE_DATA lpFileInfo;

		if (GetFileAttributesExW(AFileName, GetFileExInfoStandard, &lpFileInfo)) {			
			AFileSize.HighPart = lpFileInfo.nFileSizeHigh;
			AFileSize.LowPart = lpFileInfo.nFileSizeLow;
		}
	}
	
	return AFileSize.QuadPart;
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		cout << "Usage : readeof.exe \"C:\\suspicious.exe\"" << endl;

		return 0;
	}

	wchar_t AFileName[MAX_PATH] = { 0 };

	for (int i = 0; i < strlen(argv[1]); i++) {
		AFileName[i] = argv[1][i];
	}

	//GetModuleFileNameW(0, AFileName, MAX_PATH);	

	wcout << "Working on \"" << AFileName << "\" : " << endl << endl;

	/*
		Get target file size on disk.
	*/
	__int64 AFileSize = GetFileSize(AFileName);
	if (AFileSize <= 0) {
		log_error("Could not get target file size on disk. Abort.");

		return 0;
	}

	log_success("File size on disk : " + to_string(AFileSize) + " bytes");

	/*
		Now we will compare with image size described by the PE Header.
	*/
	DWORD dwBytesRead = 0;	

	HANDLE hFile = CreateFile(AFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		log_error("Could not open target file.");

		return 0;
	}

	SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);		

	/*
		Read IMAGE_DOS_HEADER
	*/
	IMAGE_DOS_HEADER AImageDosHeader;

	if (!ReadFile(hFile, &AImageDosHeader, sizeof(IMAGE_DOS_HEADER), &dwBytesRead, nullptr)) {
		log_error("Could not read IMAGE_DOS_HEADER.");

		CloseHandle(hFile);

		return 0;
	}

	if (AImageDosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
		log_error("Not a valid PE File.");

		CloseHandle(hFile);

		return 0;
	}

	SetFilePointer(hFile, AImageDosHeader.e_lfanew, nullptr, FILE_BEGIN);

	/*
		Verify if if we match IMAGE_NT_SIGNATURE (0x4550)
	*/

	DWORD AImageNTSignature;

	if (!ReadFile(hFile, &AImageNTSignature, sizeof(DWORD), &dwBytesRead, nullptr)) {
		log_error("Could not read IMAGE_NT_SIGNATURE.");

		CloseHandle(hFile);

		return 0;
	}

	if (AImageNTSignature != IMAGE_NT_SIGNATURE) {
		log_error("IMAGE_NT_SIGNATURE Doesn't match.");

		CloseHandle(hFile);

		return 0;
	}

	log_success("The file is likely a valid PE File.");

	/*
		At this point, we are enough sure we are facing a valid PE File.
		Reading IMAGE_FILE_HEADER
	*/
	IMAGE_FILE_HEADER AImageFileHeader;

	if (!ReadFile(hFile, &AImageFileHeader, sizeof(IMAGE_FILE_HEADER), &dwBytesRead, nullptr)) {
		cout << "Could not read IMAGE_FILE_HEADER." << endl;

		CloseHandle(hFile);

		return 0;
	}

	// Checking if we are facing a x64 or x86 PE File.
	bool x64 = (AImageFileHeader.Machine == IMAGE_FILE_MACHINE_AMD64);

	log_debug(string("Facing ") + (x64 ? "64" : "32") + string("bit PE File."));

	__int64 AImageSize = 0;

	/*
		Reading IMAGE_OPTIONAL_HEADER. Support both x64 and x64.
	*/
	if (x64) {
		IMAGE_OPTIONAL_HEADER64 AOptionalHeader;

		if (!ReadFile(hFile, &AOptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER64), &dwBytesRead, nullptr)) {
			log_error("Could not read IMAGE_OPTIONAL_HEADER64");

			CloseHandle(hFile);

			return 0;
		}

		/*
			We don't forget to add the IMAGE_DIRERCTORY_ENTRY_SECURITY if target application is signed otherwise
			the full image size wont match.
		*/
		AImageSize += (__int64(AOptionalHeader.SizeOfHeaders) + __int64(AOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size));
	}
	else {
		IMAGE_OPTIONAL_HEADER32 AOptionalHeader;

		if (!ReadFile(hFile, &AOptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER32), &dwBytesRead, nullptr)) {
			log_error("Could not read IMAGE_OPTIONAL_HEADER32");

			CloseHandle(hFile);

			return 0;
		}

		// Same as above
		AImageSize += (__int64(AOptionalHeader.SizeOfHeaders) + __int64(AOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size));
	}


	/*
		Enumerate each sections, and append to our current mesured image size.
	*/
	for (int i = 0; i < AImageFileHeader.NumberOfSections; i++) {
		IMAGE_SECTION_HEADER AImageSectionHeader;

		if (!ReadFile(hFile, &AImageSectionHeader, sizeof(IMAGE_SECTION_HEADER), &dwBytesRead, nullptr)) {
			log_error("Fail to read section n°" + to_string(i));

			CloseHandle(hFile);

			return 0; // If one section fail to be read, then we loose.
		}

		AImageSize += AImageSectionHeader.SizeOfRawData;
	}

	log_success("Image Size successfully calculated : " + to_string(AImageSize) + " bytes");

	/*
		Checking if some EOF data is present in target file.
	*/
	unsigned AEOFSize = (AFileSize - AImageSize);
	
	if (AEOFSize > 0) {
		log_warn(to_string(AEOFSize) + " bytes of EOF Data detected.");

		/*
			Read EOF Data
		*/
		log_debug("Extracting / Printing EOF Data:");
		cout << endl;

		SetFilePointer(hFile, (AFileSize - AEOFSize), nullptr, FILE_BEGIN); // Could also use FILE_END

		PVOID pBuffer = malloc(AEOFSize);

		if (!ReadFile(hFile, pBuffer, AEOFSize, &dwBytesRead, nullptr)) {
			log_error("Could not read EOF data.");
		}
		else {
			/*
				Print EOF data.
			*/
			HexDumpBufferToConsole(pBuffer, AEOFSize);						
		}

		/*
			Offering user to dump EOF Data to file
		*/
		cout << "Do you want to dump the content of EOF Data ? (y/n) : ";

		string s = "";
		cin.width(1); // we only take care of first character.
		cin >> s;

		if (s == "y") { 
			cout << "Output file path : ";

			wstring AOutputPath;

			cin.width(MAX_PATH);

			wcin >> AOutputPath;

			/*
				Write EOF data to file
			*/
			DWORD AErrorCode = 0;
			if (!WriteBufferToFile(pBuffer, AEOFSize, AOutputPath, &AErrorCode)) {
				log_error("Could no write EOF data to file with error " + to_string(AErrorCode));
			} 
			else
			{
				log_success("EOF data successfully dumped.");
			};
		}

		free(pBuffer);
	}
	else {
		log_success("No EOF data detected so far.");
	}

	CloseHandle(hFile);

	return 0;
}