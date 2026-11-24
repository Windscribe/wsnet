#pragma once

#include <curl/curl.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

namespace wsnet {

BIO_METHOD *tlsRecordSplitBioMethod();
CURLcode installTlsRecordSplitCtx(CURL *curl, void *sslctx, void *parm);

}
