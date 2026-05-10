#pragma once
#include <QByteArray>
#include <QFile>
#include <QDebug>
#include <cstring>
#include <cstdint>

// ============================================================
// Глобальные данные NG криптографии
// ============================================================
static uint8_t  g_ng_keys[101][272];      // 101 ключ по 272 байт (17 раундов * 16 байт)
static uint32_t g_ng_tables[17][16][256]; // таблицы [раунд][колонка][байт]
static uint8_t  g_ng_lut[256];
static bool     g_ng_loaded = false;

static const int NG_KEY_COUNT = 101;

// ============================================================
// Загрузка ключей
// ============================================================
bool loadNgKeys(const QString &keysDir) {
    // gtav_ng_key.dat — 101 * 272 = 27472 байт
    {
        QFile f(keysDir + "/gtav_ng_key.dat");
        if (!f.open(QIODevice::ReadOnly)) { qWarning() << "Cannot open gtav_ng_key.dat"; return false; }
        QByteArray data = f.readAll(); f.close();
        if (data.size() < 101 * 272) { qWarning() << "gtav_ng_key.dat too small:" << data.size(); return false; }
        for (int i = 0; i < 101; i++)
            memcpy(g_ng_keys[i], data.constData() + i * 272, 272);
        qDebug() << "NG keys loaded OK (101 keys x 272 bytes)";
    }
    // gtav_ng_decrypt_tables.dat — 17*16*256*4 = 278528 байт
    {
        QFile f(keysDir + "/gtav_ng_decrypt_tables.dat");
        if (!f.open(QIODevice::ReadOnly)) { qWarning() << "Cannot open gtav_ng_decrypt_tables.dat"; return false; }
        QByteArray data = f.readAll(); f.close();
        if (data.size() < 17 * 16 * 256 * 4) { qWarning() << "gtav_ng_decrypt_tables.dat too small"; return false; }
        const uint32_t *ptr = reinterpret_cast<const uint32_t*>(data.constData());
        for (int i = 0; i < 17; i++)
            for (int j = 0; j < 16; j++)
                for (int k = 0; k < 256; k++)
                    g_ng_tables[i][j][k] = ptr[i * 16 * 256 + j * 256 + k];
        qDebug() << "NG decrypt tables loaded OK (17x16x256)";
    }
    // gtav_hash_lut.dat — 256 байт
    {
        QFile f(keysDir + "/gtav_hash_lut.dat");
        if (!f.open(QIODevice::ReadOnly)) { qWarning() << "Cannot open gtav_hash_lut.dat"; return false; }
        QByteArray data = f.readAll(); f.close();
        if (data.size() < 256) { qWarning() << "gtav_hash_lut.dat too small"; return false; }
        memcpy(g_ng_lut, data.constData(), 256);
        qDebug() << "LUT loaded OK";
    }
    g_ng_loaded = true;
    qDebug() << "All NG crypto data loaded!";
    return true;
}

// ============================================================
// Точный порт из GTACrypto.cs
// ============================================================

// Хэш имени файла через LUT (GTA5Hash.CalculateHash)
static uint32_t gta5Hash(const QString &name) {
    QByteArray bytes = name.toLower().toLatin1();
    uint32_t result = 0;
    for (int i = 0; i < bytes.size(); i++) {
        uint8_t c = static_cast<uint8_t>(bytes[i]);
        uint32_t temp = 1025 * (static_cast<uint32_t>(g_ng_lut[c]) + result);
        result = (temp >> 6) ^ temp;
    }
    return 32769 * ((9 * result >> 11) ^ (9 * result));
}

// GetNGKey: (hash + length + 61) % 101
static int getKeyIndex(const QString &name, uint32_t length) {
    QString n = name.toLower();
    int slash = qMax(n.lastIndexOf('/'), n.lastIndexOf('\\'));
    if (slash >= 0) n = n.mid(slash + 1);
    uint32_t hash = gta5Hash(n);
    return static_cast<int>((hash + length + 61) % static_cast<uint32_t>(NG_KEY_COUNT));
}

// DecryptNGRoundA — раунды 0, 1, 16
// Таблицы уже содержат XOR с ключом!
// table[col][data[col]] уже включает key XOR внутри таблицы
static void decryptNGRoundA(uint8_t *out, const uint8_t *data, int round, const uint32_t *subkey) {
    uint32_t x1 = g_ng_tables[round][ 0][data[ 0]] ^ g_ng_tables[round][ 1][data[ 1]] ^
                  g_ng_tables[round][ 2][data[ 2]] ^ g_ng_tables[round][ 3][data[ 3]] ^ subkey[0];
    uint32_t x2 = g_ng_tables[round][ 4][data[ 4]] ^ g_ng_tables[round][ 5][data[ 5]] ^
                  g_ng_tables[round][ 6][data[ 6]] ^ g_ng_tables[round][ 7][data[ 7]] ^ subkey[1];
    uint32_t x3 = g_ng_tables[round][ 8][data[ 8]] ^ g_ng_tables[round][ 9][data[ 9]] ^
                  g_ng_tables[round][10][data[10]] ^ g_ng_tables[round][11][data[11]] ^ subkey[2];
    uint32_t x4 = g_ng_tables[round][12][data[12]] ^ g_ng_tables[round][13][data[13]] ^
                  g_ng_tables[round][14][data[14]] ^ g_ng_tables[round][15][data[15]] ^ subkey[3];
    memcpy(out +  0, &x1, 4);
    memcpy(out +  4, &x2, 4);
    memcpy(out +  8, &x3, 4);
    memcpy(out + 12, &x4, 4);
}

// DecryptNGRoundB — раунды 2..15
static void decryptNGRoundB(uint8_t *out, const uint8_t *data, int round, const uint32_t *subkey) {
    uint32_t x1 = g_ng_tables[round][ 0][data[ 0]] ^ g_ng_tables[round][ 7][data[ 7]] ^
                  g_ng_tables[round][10][data[10]] ^ g_ng_tables[round][13][data[13]] ^ subkey[0];
    uint32_t x2 = g_ng_tables[round][ 1][data[ 1]] ^ g_ng_tables[round][ 4][data[ 4]] ^
                  g_ng_tables[round][11][data[11]] ^ g_ng_tables[round][14][data[14]] ^ subkey[1];
    uint32_t x3 = g_ng_tables[round][ 2][data[ 2]] ^ g_ng_tables[round][ 5][data[ 5]] ^
                  g_ng_tables[round][ 8][data[ 8]] ^ g_ng_tables[round][15][data[15]] ^ subkey[2];
    uint32_t x4 = g_ng_tables[round][ 3][data[ 3]] ^ g_ng_tables[round][ 6][data[ 6]] ^
                  g_ng_tables[round][ 9][data[ 9]] ^ g_ng_tables[round][12][data[12]] ^ subkey[3];
    out[ 0] = (x1 >>  0) & 0xFF; out[ 1] = (x1 >>  8) & 0xFF;
    out[ 2] = (x1 >> 16) & 0xFF; out[ 3] = (x1 >> 24) & 0xFF;
    out[ 4] = (x2 >>  0) & 0xFF; out[ 5] = (x2 >>  8) & 0xFF;
    out[ 6] = (x2 >> 16) & 0xFF; out[ 7] = (x2 >> 24) & 0xFF;
    out[ 8] = (x3 >>  0) & 0xFF; out[ 9] = (x3 >>  8) & 0xFF;
    out[10] = (x3 >> 16) & 0xFF; out[11] = (x3 >> 24) & 0xFF;
    out[12] = (x4 >>  0) & 0xFF; out[13] = (x4 >>  8) & 0xFF;
    out[14] = (x4 >> 16) & 0xFF; out[15] = (x4 >> 24) & 0xFF;
}

// DecryptNGBlock — точный порт DecryptNGBlock из GTACrypto.cs
static void decryptNGBlock(uint8_t *block, int keyIndex) {
    const uint8_t *key = g_ng_keys[keyIndex % NG_KEY_COUNT];

    // Subkeys: key[4*i..4*i+3] как uint32
    uint32_t subKeys[17][4];
    for (int i = 0; i < 17; i++) {
        memcpy(subKeys[i], key + i * 16, 16);
    }

    uint8_t buf[16];
    memcpy(buf, block, 16);
    uint8_t tmp[16];

    decryptNGRoundA(tmp, buf, 0, subKeys[0]);  memcpy(buf, tmp, 16);
    decryptNGRoundA(tmp, buf, 1, subKeys[1]);  memcpy(buf, tmp, 16);
    for (int k = 2; k <= 15; k++) {
        decryptNGRoundB(tmp, buf, k, subKeys[k]); memcpy(buf, tmp, 16);
    }
    decryptNGRoundA(tmp, buf, 16, subKeys[16]); memcpy(buf, tmp, 16);

    memcpy(block, buf, 16);
}

// ============================================================
// Публичные функции
// ============================================================
QByteArray decryptNG(const QByteArray &input, const QString &fileName, uint32_t fileSize) {
    if (!g_ng_loaded) { qWarning() << "NG keys not loaded!"; return input; }
    QByteArray output = input;
    uint8_t *data = reinterpret_cast<uint8_t*>(output.data());
    int blocks = output.size() / 16;
    int keyIndex = getKeyIndex(fileName, fileSize);
    qDebug() << "NG keyIndex:" << keyIndex << "for" << fileName << "size" << fileSize;
    for (int i = 0; i < blocks; i++)
        decryptNGBlock(data + i * 16, keyIndex);
    return output;
}

QByteArray decryptNGwithKey(const QByteArray &input, int keyIndex) {
    if (!g_ng_loaded) { qWarning() << "NG keys not loaded!"; return input; }
    QByteArray output = input;
    uint8_t *data = reinterpret_cast<uint8_t*>(output.data());
    int blocks = output.size() / 16;
    for (int i = 0; i < blocks; i++)
        decryptNGBlock(data + i * 16, keyIndex);
    return output;
}
