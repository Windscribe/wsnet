#include "tlsrecordsplitbio.h"
#include <algorithm>
#include <cstdint>
#include <cstring>

namespace wsnet {

namespace {

struct SplitBioState {
    std::uint8_t inBuf[7] = {};
    std::size_t inLen = 0;
    std::uint8_t outHdr[12] = {};
    std::size_t outHdrLen = 0;
    std::size_t outHdrSent = 0;
    bool headerDone = false;
    bool passthrough = false;
};

int splitBioCreate(BIO *b)
{
    auto *st = new SplitBioState();
    BIO_set_data(b, st);
    BIO_set_init(b, 1);
    return 1;
}

int splitBioDestroy(BIO *b)
{
    if (!b) {
        return 0;
    }
    auto *st = static_cast<SplitBioState *>(BIO_get_data(b));
    delete st;
    BIO_set_data(b, nullptr);
    BIO_set_init(b, 0);
    return 1;
}

int flushPendingHeader(BIO *b, BIO *next, SplitBioState *st)
{
    while (st->outHdrSent < st->outHdrLen) {
        std::size_t chunk = st->outHdrLen - st->outHdrSent;
        if (st->outHdrLen == 12 && st->outHdrSent < 7) {
            chunk = 7 - st->outHdrSent;
        }
        int w = BIO_write(next, st->outHdr + st->outHdrSent, static_cast<int>(chunk));
        BIO_clear_retry_flags(b);
        if (w <= 0) {
            BIO_copy_next_retry(b);
            return w;
        }
        st->outHdrSent += static_cast<std::size_t>(w);
    }
    st->passthrough = true;
    return 1;
}

int splitBioWrite(BIO *b, const char *in, int inl)
{
    BIO *next = BIO_next(b);
    if (!next || !in || inl <= 0) {
        return 0;
    }
    auto *st = static_cast<SplitBioState *>(BIO_get_data(b));
    if (!st || st->passthrough) {
        int n = BIO_write(next, in, inl);
        BIO_clear_retry_flags(b);
        if (n <= 0) {
            BIO_copy_next_retry(b);
        }
        return n;
    }

    if (st->outHdrSent < st->outHdrLen) {
        int fr = flushPendingHeader(b, next, st);
        if (fr <= 0) {
            return fr;
        }
        int n = BIO_write(next, in, inl);
        BIO_clear_retry_flags(b);
        if (n <= 0) {
            BIO_copy_next_retry(b);
        }
        return n;
    }

    std::size_t consumed = 0;
    if (!st->headerDone) {
        std::size_t take = std::min<std::size_t>(7 - st->inLen, static_cast<std::size_t>(inl));
        std::memcpy(st->inBuf + st->inLen, in, take);
        st->inLen += take;
        consumed = take;
        if (st->inLen < 7) {
            return static_cast<int>(consumed);
        }

        std::uint16_t recLen = static_cast<std::uint16_t>((static_cast<std::uint16_t>(st->inBuf[3]) << 8) | st->inBuf[4]);
        if (st->inBuf[0] == 0x16 && st->inBuf[1] == 0x03 && recLen >= 3 && st->inBuf[5] == 0x01) {
            std::uint16_t rem = static_cast<std::uint16_t>(recLen - 2);
            st->outHdr[0] = 0x16;
            st->outHdr[1] = st->inBuf[1];
            st->outHdr[2] = st->inBuf[2];
            st->outHdr[3] = 0x00;
            st->outHdr[4] = 0x02;
            st->outHdr[5] = st->inBuf[5];
            st->outHdr[6] = st->inBuf[6];
            st->outHdr[7] = 0x16;
            st->outHdr[8] = st->inBuf[1];
            st->outHdr[9] = st->inBuf[2];
            st->outHdr[10] = static_cast<std::uint8_t>(rem >> 8);
            st->outHdr[11] = static_cast<std::uint8_t>(rem & 0xFF);
            st->outHdrLen = 12;
        } else {
            std::memcpy(st->outHdr, st->inBuf, 7);
            st->outHdrLen = 7;
        }
        st->outHdrSent = 0;
        st->headerDone = true;

        int fr = flushPendingHeader(b, next, st);
        if (fr <= 0) {
            return static_cast<int>(consumed);
        }
    }

    if (consumed < static_cast<std::size_t>(inl)) {
        int tail = BIO_write(next, in + consumed, static_cast<int>(inl - consumed));
        BIO_clear_retry_flags(b);
        if (tail > 0) {
            return static_cast<int>(consumed) + tail;
        }
        BIO_copy_next_retry(b);
        return static_cast<int>(consumed);
    }

    return static_cast<int>(consumed);
}

int splitBioRead(BIO *b, char *out, int outl)
{
    BIO *next = BIO_next(b);
    if (!next) {
        return 0;
    }
    int n = BIO_read(next, out, outl);
    BIO_clear_retry_flags(b);
    if (n <= 0) {
        BIO_copy_next_retry(b);
    }
    return n;
}

long splitBioCtrl(BIO *b, int cmd, long num, void *ptr)
{
    BIO *next = BIO_next(b);
    if (!next) {
        return 0;
    }
    if (cmd == BIO_CTRL_DUP) {
        return 1;
    }
    long ret = BIO_ctrl(next, cmd, num, ptr);
    BIO_clear_retry_flags(b);
    if (ret <= 0 && BIO_should_retry(next)) {
        BIO_copy_next_retry(b);
    }
    return ret;
}

int splitBioExDataIndex()
{
    static int idx = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return idx;
}

void onSslHandshakeInfo(const SSL *sslConst, int where, int)
{
    if ((where & SSL_CB_HANDSHAKE_START) == 0) {
        return;
    }
    SSL *ssl = const_cast<SSL *>(sslConst);
    int idx = splitBioExDataIndex();
    if (SSL_get_ex_data(ssl, idx) != nullptr) {
        return;
    }
    BIO *orig = SSL_get_wbio(ssl);
    if (!orig) {
        return;
    }
    BIO *filter = BIO_new(tlsRecordSplitBioMethod());
    if (!filter) {
        return;
    }
    BIO_up_ref(orig);
    BIO *chained = BIO_push(filter, orig);
    SSL_set0_wbio(ssl, chained);
    SSL_set_ex_data(ssl, idx, reinterpret_cast<void *>(1));
}

}

BIO_METHOD *tlsRecordSplitBioMethod()
{
    static BIO_METHOD *method = []() {
        BIO_METHOD *m = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_FILTER, "wsnet_tls_rec_split");
        BIO_meth_set_write(m, splitBioWrite);
        BIO_meth_set_read(m, splitBioRead);
        BIO_meth_set_ctrl(m, splitBioCtrl);
        BIO_meth_set_create(m, splitBioCreate);
        BIO_meth_set_destroy(m, splitBioDestroy);
        return m;
    }();
    return method;
}

CURLcode installTlsRecordSplitCtx(CURL *, void *sslctx, void *)
{
    auto *ctx = static_cast<SSL_CTX *>(sslctx);
    SSL_CTX_set_info_callback(ctx, onSslHandshakeInfo);
    return CURLE_OK;
}

}
