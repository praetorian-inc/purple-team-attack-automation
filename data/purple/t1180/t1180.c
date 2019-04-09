#include <process.h>

int main( void )
{
    system("cmd /c calc.exe && echo T1180 > C:\\t1180.txt && whoami >> C:\\t1180.txt && date /t >> C:\\t1180.txt && time /t >> C:\\t1180.txt");
}