#include "stringTools.h"
#include "stdafx.h"

int forceNullTermination(char* string, unsigned int len)
{
    if(string[len] != 0)
        string[len] = 0;
    return 1;
}
