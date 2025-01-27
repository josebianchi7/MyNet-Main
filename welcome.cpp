/*
Name: Jose Bianchi 
GitHub username: josebianchi7
Description: Program Welcome Page
*/

#include <iostream>         // iostream affords input and output via the console
#include <ostream>
#include <string>           // includes string methods            
// #include <cmath>            // includes methods like sqrt(), abs(), power(base, exp)
// #include <stdlib.h>         // includes functions for program termination, resource cleanup, and random using rand() and srand()
// #include <ctime>            // includes functions for processing time, system time, and run time of a program
// #include <chrono>           // allows use of clock time in miliseconds
// #include <vector>           // affords use of dynamic arrays

// #include <my_functions.hpp> // header file for various function call

int main() {
    
    std::cout<<"\n";
    std::cout<<"MyNet\n\n";
    std::cout<<"Welcome to the MyNet home network protection program!\n\n";

    std::cout<<"*Be advised pressing the Ctrl key and 'C' will immediately end this program from any screen.\n\n";

    std::cout<<" Enter an option number to continue.\n\n"; 
    std::cout<<"  1) Current Activity\n\n";
    std::cout<<"  2) Log Report\n\n";
    std::cout<<"  0) Information/ Help\n";
    
    int response = 9;

    std::cin >> response;

    return 0;
}