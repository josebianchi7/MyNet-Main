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
    std::cout<<"Information and Resources\n\n";

    std::cout<<"Hello, this program is a home network protection tool.\n\n";
    std::cout<<"With this version, you can see devices currently on your network.\n";
    std::cout<<"This program will also log network events. These network events\n";    
    std::cout<<"include when a device connects to your network. If an event like \n";    
    std::cout<<"this occurs, and if the device is registered, then the program\n";
    std::cout<<"shows the registered device name. If the device is not registered,\n";
    std::cout<<"detailed data about the unknown device is stored to the log. Users\n";
    std::cout<<"can then use the data presented and stored by this program to gain\n";
    std::cout<<"more confidence in their network's security or find out if additional\n";
    std::cout<<"measures may need to be implemented.\n\n";
    
    std::cout<<"For further questions or concerns, please contact the developer,\n";
    std::cout<<"Jose Bianchi at bianchjo@oregonstate.edu.\n\n";

    std::cout<<" Enter an option number to continue.\n\n"; 
    std::cout<<"  1) Current Activity\n\n";
    std::cout<<"  2) Log Report\n\n";
    
    int response = 9;

    std::cin >> response;

    return 0;
}