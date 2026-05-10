#pragma once
#include <QByteArray>
#include <QFile>
#include <QDebug>

extern "C" {
#include "aes.h"
}

static QByteArray g_aesKey;

bool loadAesKey(const QString &path) {
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        qWarning() << "Cannot open key file:" << path;
        return false;
    }
    g_aesKey = f.readAll();
    if (g_aesKey.size() != 32) {
        qWarning() << "Invalid key size:" << g_aesKey.size() << "(expected 32)";
        return false;
    }
    qDebug() << "AES key loaded:" << g_aesKey.toHex();
    return true;
}

QByteArray decryptAES256(const QByteArray &input) {
    if (g_aesKey.size() != 32) {
        qWarning() << "Key not loaded!";
        return input;
    }

    QByteArray output = input;
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, reinterpret_cast<const uint8_t*>(g_aesKey.constData()));

    uint8_t *data = reinterpret_cast<uint8_t*>(output.data());
    int blocks = output.size() / 16;

    for (int i = 0; i < blocks; i++) {
        AES_ECB_decrypt(&ctx, data + i * 16);  // один раз на блок
    }
    return output;
}
