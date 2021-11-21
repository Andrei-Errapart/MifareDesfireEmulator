#ifndef proxydriver_h_
#define proxydriver_h_

#include <nfc/nfc.h>

#if defined(__cplusplus)
extern "C" {
#endif

extern nfc_driver* proxydriver_new(const char* host, const int port);

#if defined(__cplusplus)
}
#endif

#endif /* proxydriver_h_ */

