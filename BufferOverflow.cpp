// BufferOverflow.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <cstring>    // for strncpy_s and strnlen

// DO NOT CHANGE
const size_t INPUT_BUFFER_SIZE = 8;
const size_t ACCOUNT_BUFFER_SIZE = 16;

// DO NOT CHANGE
void displayAccount(const char* tag, const char* account)
{
    std::cout << tag << account << std::endl;
}

// TODO: Modify this to detect and prevent buffer overflow
// - If input length >= INPUT_BUFFER_SIZE, print a message and return false
// - Otherwise copy safely and return true
bool getUserInput(char* userBuffer, size_t bufferSize)
{
    char temp[100];
    std::cout << "Enter account number: ";
    std::cin.getline(temp, sizeof(temp));

    // measure actual input length (up to std::cin limit)
    size_t len = strnlen(temp, sizeof(temp));
    if (len >= bufferSize) {
        // notify the caller and the user
        std::cout
            << "Buffer overflow detected and prevented. "
            << "Input length " << len
            << " exceeds buffer size " << bufferSize
            << std::endl;
        return false;
    }

    // safe copy using the “secure” CRT function
    // strncpy_s will null-terminate and fail if temp is longer than bufferSize-1
    strncpy_s(userBuffer, bufferSize, temp, bufferSize - 1);
    userBuffer[bufferSize - 1] = '\0';
    return true;
}

// DO NOT CHANGE
int main()
{
    char userAccount[INPUT_BUFFER_SIZE];
    char secretAccount[ACCOUNT_BUFFER_SIZE] = "SECRET-123456";

    // attempt to get user input safely
    if (!getUserInput(userAccount, INPUT_BUFFER_SIZE)) {
        std::cout << "Failed to read account number safely. Terminating." << std::endl;
        return 1;
    }

    // display both numbers
    displayAccount("You entered:      ", userAccount);
    displayAccount("Secret account is:", secretAccount);

    return 0;
}



// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu
