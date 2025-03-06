#include <stdarg.h>
#include "tyche.h"

#define MAX_PRINTF_LENGTH 1024
#define DEBUG_PREFIX "[MUSL] "
#define DEBUG_PREFIX_LEN 7  // Length of "[MUSL] "

// Custom function to reverse a string
void reverse(char* str, int length) {
    int start = 0;
    int end = length - 1;
    while (start < end) {
        char temp = str[start];
        str[start] = str[end];
        str[end] = temp;
        start++;
        end--;
    }
}

// Custom function to convert integer to string
int int_to_string(long long num, char* str, int base) {
    int i = 0;
    int is_negative = 0;

    // Handle 0 explicitly
    if (num == 0) {
        str[i++] = '0';
        str[i] = '\0';
        return i;
    }

    // Handle negative numbers for decimal
    if (num < 0 && base == 10) {
        is_negative = 1;
        num = -num;
    }

    // Process individual digits
    while (num != 0) {
        int rem = num % base;
        str[i++] = (rem > 9) ? (rem - 10) + 'a' : rem + '0';
        num = num / base;
    }

    // Append negative sign for decimal
    if (is_negative)
        str[i++] = '-';

    str[i] = '\0';
    reverse(str, i);
    return i;
}

// Function to format a string
int format_string(char *buffer, size_t buffer_size, const char *format, va_list args) {
    int written = 0;
    char *bufptr = buffer;

    const char *ptr = format;
    while (*ptr != '\0' && written < buffer_size - 1) {
        if (*ptr == '%') {
            ptr++;
            int is_long_long = 0;
            if (*ptr == 'l' && *(ptr+1) == 'l') {
                is_long_long = 1;
                ptr += 2;
            }
            switch (*ptr) {
                case 'd': {
                    long long val = is_long_long ? va_arg(args, long long) : va_arg(args, int);
                    char num_str[32];
                    int len = int_to_string(val, num_str, 10);
                    for (int i = 0; i < len && written < buffer_size - 1; i++) {
                        *bufptr++ = num_str[i];
                        written++;
                    }
                    break;
                }
                case 'x': {
                    unsigned long long val = is_long_long ? va_arg(args, unsigned long long) : va_arg(args, unsigned int);
                    char num_str[32];
                    int len = int_to_string(val, num_str, 16);
                    for (int i = 0; i < len && written < buffer_size - 1; i++) {
                        *bufptr++ = num_str[i];
                        written++;
                    }
                    break;
                }
                case 'c': {
                    char c = (char) va_arg(args, int);
                    *bufptr++ = c;
                    written++;
                    break;
                }
                case 's': {
                    const char *s = va_arg(args, const char*);
                    while (*s != '\0' && written < buffer_size - 1) {
                        *bufptr++ = *s++;
                        written++;
                    }
                    break;
                }
                case '%':
                    *bufptr++ = '%';
                    written++;
                    break;
                default:
                    *bufptr++ = '%';
                    if (is_long_long) {
                        *bufptr++ = 'l';
                        *bufptr++ = 'l';
                        written += 2;
                    }
                    *bufptr++ = *ptr;
                    written += 2;
                    break;
            }
        } else {
            *bufptr++ = *ptr;
            written++;
        }
        ptr++;
    }

    *bufptr = '\0';
    return written;
}


void tyche_log_char_buffer(char* buff, int size) {
    char output[MAX_PRINTF_LENGTH];
    int written = 0;

    for (int i = 0; i < size && written < MAX_PRINTF_LENGTH - 1; i++) {
        // Format each byte as two hex digits
        unsigned char byte = (unsigned char)buff[i];
        char byte_str[3];
        byte_str[0] = "0123456789abcdef"[byte >> 4];
        byte_str[1] = "0123456789abcdef"[byte & 0xF];
        byte_str[2] = ' ';

        if (written + 3 <= MAX_PRINTF_LENGTH - 1) {
            for (int j = 0; j < 3; j++) {
                output[written++] = byte_str[j];
            }
        }

        // Add a newline every 16 bytes (48 characters including spaces) for readability
        if ((i + 1) % 16 == 0 || i == size - 1) {
            if (written < MAX_PRINTF_LENGTH - 1) {
                output[written++] = '\n';
            }
        }
    }

    // Null-terminate the string
    output[written] = '\0';

    // Print the entire buffer contents with one call to tyche_log
    tyche_write(1, output, written);
}

int tyche_log(const char *format, ...) {
    char buffer[MAX_PRINTF_LENGTH];
    int prefix_len = 0;
    
    // Add debug prefix
    for (int i = 0; i < DEBUG_PREFIX_LEN && prefix_len < MAX_PRINTF_LENGTH - 1; i++) {
        buffer[prefix_len++] = DEBUG_PREFIX[i];
    }

    va_list args;
    va_start(args, format);

    int formatted_len = format_string(buffer + prefix_len, MAX_PRINTF_LENGTH - prefix_len, format, args);

    va_end(args);

    int total_len = prefix_len + formatted_len;
    return tyche_write(1, buffer, total_len);  // Assuming 1 is the file descriptor for stdout
}