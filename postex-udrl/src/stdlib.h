#include <windows.h>

void* _memset(void* dest, int ch, size_t count) {
    unsigned char* p = (unsigned char*)dest;
    unsigned char value = (unsigned char)ch;

    for (size_t i = 0; i < count; i++) {
        p[i] = value;
    }

    return dest;
}

int _strncmp(const char *s1, const char *s2, size_t n) {
    while (n-- > 0) {
        unsigned char c1 = (unsigned char)*s1++;
        unsigned char c2 = (unsigned char)*s2++;
        
        if (c1 != c2)
            return c1 - c2;
        
        if (c1 == '\0')
            break;
    }
    
    return 0;
}
