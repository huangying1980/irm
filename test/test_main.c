/* huangying */
#include <string.h>
#include "test_msg.h"


int main(int argc, char* argv[])
{
    if (strcasestr(argv[0], "test_pub")) { 
        test_pub(argc, argv);
    }
    if (strcasestr(argv[0], "test_unremitting_pub")) {
        test_unremitting_pub(argc, argv);
    }
    if (strcasestr(argv[0], "test_sub")) {
        test_sub(argc, argv);
    }
    if (strcasestr(argv[0], "test_ping")) {
        test_ping(argc, argv);
    }
    if (strcasestr(argv[0], "test_pong")) {
        test_pong(argc, argv);
    }
    return 0;
}
