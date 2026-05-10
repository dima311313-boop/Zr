#pragma once
#include <QFile>
#include <QDebug>
#include <QCryptographicHash>
#include <QDir>
#include "cryptography_hashes.h"

static const int NG_KEY_SIZE   = 0x110;
static const int NG_TABLE_SIZE = 0x400;
static const int NG_KEY_COUNT  = 101;
static const int NG_TABLE_COUNT = 272;

// Ищет блок в exe по SHA1 и возвращает смещение
static int findBlockByHash(const QByteArray &exe, const uint8_t *targetHash, int blockSize) {
    for (int offset = 0; offset <= exe.size() - blockSize; offset += 16) {
        QByteArray block = exe.mid(offset, blockSize);
        QByteArray hash = QCryptographicHash::hash(block, QCryptographicHash::Sha1);
        if (memcmp(hash.constData(), targetHash, 20) == 0)
            return offset;
    }
    return -1;
}

bool extractNgData(const QString &exePath, const QString &outDir) {
    qDebug() << "Reading GTA5.exe...";
    QFile exe(exePath);
    if (!exe.open(QIODevice::ReadOnly)) {
        qWarning() << "Cannot open GTA5.exe";
        return false;
    }
    QByteArray data = exe.readAll();
    exe.close();
    qDebug() << "Loaded" << data.size() << "bytes";

    QDir().mkpath(outDir);

    // Ищем все NG ключи
    qDebug() << "Searching for NG keys...";
    int keysFound = 0;
    for (int i = 0; i < NG_KEY_COUNT; i++) {
        int offset = findBlockByHash(data, PC_NG_KEY_HASHES[i], NG_KEY_SIZE);
        if (offset >= 0) {
            QFile out(outDir + QString("/ng_key_%1.dat").arg(i));
            out.open(QIODevice::WriteOnly);
            out.write(data.mid(offset, NG_KEY_SIZE));
            keysFound++;
        }
        if (i % 10 == 0)
            qDebug() << QString("Keys: %1/%2 (found: %3)").arg(i).arg(NG_KEY_COUNT).arg(keysFound);
    }
    qDebug() << "Keys found:" << keysFound;

    // Ищем все NG таблицы
    qDebug() << "Searching for NG tables...";
    int tablesFound = 0;
    for (int i = 0; i < NG_TABLE_COUNT; i++) {
        int offset = findBlockByHash(data, PC_NG_DECRYPT_TABLE_HASHES[i], NG_TABLE_SIZE);
        if (offset >= 0) {
            QFile out(outDir + QString("/ng_table_%1.dat").arg(i));
            out.open(QIODevice::WriteOnly);
            out.write(data.mid(offset, NG_TABLE_SIZE));
            tablesFound++;
        }
        if (i % 20 == 0)
            qDebug() << QString("Tables: %1/%2 (found: %3)").arg(i).arg(NG_TABLE_COUNT).arg(tablesFound);
    }
    qDebug() << "Tables found:" << tablesFound;

    return keysFound > 0 && tablesFound > 0;
}
