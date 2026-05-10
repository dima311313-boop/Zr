#pragma once
#include <QByteArray>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QString>
#include <QVector>
#include <cstring>
#include <cstdint>
#include "rpfreader.h"
#include "ngdecrypt.h"
#include "rpfdecrypt.h"

// ============================================================
// Структуры для удобного хранения распарсенных entries
// ============================================================
struct RpfFileNode {
    QString name;
    uint32_t dataOffset; // смещение в RPF (уже сдвинутое: rawOffset << 9)
    uint32_t dataSize;
    uint32_t flags;
    bool isResource() const { return (flags & 0x80000000) != 0; }
};

struct RpfDirNode {
    QString name;
    uint32_t entryIndex;
    uint32_t entryCount;
    QVector<RpfDirNode>  dirs;
    QVector<RpfFileNode> files;
};

// ============================================================
// Главный класс RPF архива
// ============================================================
class RpfArchive {
public:
    QString   path;
    RpfHeader header;
    int       ngKeyIndex = -1;
    QByteArray decryptedEntries;
    QByteArray decryptedNames;
    RpfDirNode root;
    bool loaded = false;

    // Открыть и распарсить RPF
    bool open(const QString &rpfPath) {
        path = rpfPath;
        QFile f(rpfPath);
        if (!f.open(QIODevice::ReadOnly)) {
            qWarning() << "Cannot open:" << rpfPath;
            return false;
        }

        f.read(reinterpret_cast<char*>(&header), sizeof(RpfHeader));
        if (header.magic != RPF7_MAGIC) {
            qWarning() << "Not RPF7:" << rpfPath;
            return false;
        }

        bool encrypted = (header.encryptionType & 0xFF) == 0xFF;

        // Entries: сразу после 16-байтного заголовка
        f.seek(0x10);
        int entriesSize = header.entryCount * 16;
        int entriesSizeAligned = (entriesSize + 15) & ~15;
        QByteArray rawEntries = f.read(entriesSizeAligned);

        // Names: сразу после entries
        int namesSizeAligned = (header.namesLength + 15) & ~15;
        QByteArray rawNames = f.read(namesSizeAligned);
        f.close();

        if (encrypted) {
            // Брутфорс ключа
            ngKeyIndex = -1;
            for (int ki = 0; ki < 101; ki++) {
                QByteArray attempt = decryptNGwithKey(rawEntries, ki);
                if (isValidEntries(attempt)) { ngKeyIndex = ki; break; }
            }
            if (ngKeyIndex < 0) { qWarning() << "NG key not found!"; return false; }
            decryptedEntries = decryptNGwithKey(rawEntries, ngKeyIndex);
            decryptedNames   = decryptNGwithKey(rawNames,   ngKeyIndex);
        } else {
            decryptedEntries = rawEntries;
            decryptedNames   = rawNames;
        }

        // Парсим дерево
        const RpfEntry *entries = reinterpret_cast<const RpfEntry*>(decryptedEntries.constData());
        root.name = QFileInfo(rpfPath).fileName();
        parseDir(root, entries, 0, header.entryCount);

        loaded = true;
        return true;
    }

    // Извлечь файл по внутреннему пути (например "common/data/effects/bloodfx.dat")
    QByteArray extractFile(const QString &internalPath) {
        if (!loaded) return {};
        QStringList parts = internalPath.split('/', Qt::SkipEmptyParts);
        RpfFileNode *node = findFile(root, parts);
        if (!node) { qWarning() << "File not found:" << internalPath; return {}; }
        return readFileData(*node);
    }

    // Читаем сырые данные файла из RPF
    QByteArray readFileData(const RpfFileNode &node) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) return {};

        uint32_t offset = node.dataOffset;
        uint32_t size   = node.dataSize;

        f.seek(offset);
        QByteArray data = f.read(size);
        f.close();

        // Расшифровка AES если нужно
        bool encrypted = (header.encryptionType & 0xFF) == 0xFF;
        if (encrypted && !node.isResource() && size >= 16) {
            data = decryptAES256(data);
        }
        return data;
    }

private:
    bool isValidEntries(const QByteArray &data) {
        if (data.size() < 16) return false;
        const RpfEntry *e = reinterpret_cast<const RpfEntry*>(data.constData());
        if (e[0].b != RPF_DIR_MARKER) return false;
        if ((e[0].a & 0xFFFF) > 512)  return false;
        if (e[0].d == 0 || e[0].d > 100000) return false;
        return true;
    }

    // Имя по смещению в блоке имён
    // nameOffset в поле 'a' — это смещение в байтах от начала блока имён
    // Но верхние 16 бит поля 'a' содержат nameOffset, нижние — что-то ещё
    QString getName(uint32_t nameOffset) {
        // nameOffset это полное поле a для dir, или нижние биты для file
        // Реальное смещение — просто nameOffset как есть
        if (nameOffset >= (uint32_t)decryptedNames.size()) return "";
        const char *ptr = decryptedNames.constData() + nameOffset;
        int maxLen = decryptedNames.size() - nameOffset;
        int len = strnlen(ptr, maxLen);
        return QString::fromLatin1(ptr, len);
    }

    void parseDir(RpfDirNode &dir, const RpfEntry *entries, uint32_t startIdx, uint32_t count) {
        // startIdx — индекс первого дочернего entry в массиве
        // count — кол-во entry в этой директории
        for (uint32_t i = startIdx; i < startIdx + count && i < header.entryCount; i++) {
            const RpfEntry &e = entries[i];
            // nameOffset — верхние 16 бит поля a (для файлов и папок)
            uint32_t nameOff = e.a & 0xFFFF;  // старшие 16 бит
            // Если не работает — попробуем нижние 16 бит
            // uint32_t nameOff = e.a & 0xFFFF;
            QString name = getName(nameOff);

            if (e.isDirectory()) {
                RpfDirNode child;
                child.name       = name;
                child.entryIndex = e.c;
                child.entryCount = e.d;
                parseDir(child, entries, e.c, e.d);
                dir.dirs.append(child);
            } else {
                RpfFileNode file;
                file.name       = name;
                file.flags      = e.d;
                // dataOffset: поле b содержит смещение >> 9 (в 512-байтных секторах)
                file.dataOffset = (e.b & 0x7FFFFF) * 512;
                // dataSize: поле c содержит размер
                file.dataSize   = e.c & 0xFFFFFF;
                dir.files.append(file);
            }
        }
    }

    RpfFileNode* findFile(RpfDirNode &dir, QStringList &parts) {
        if (parts.isEmpty()) return nullptr;
        QString first = parts.first();
        if (parts.size() == 1) {
            for (auto &f : dir.files)
                if (f.name.compare(first, Qt::CaseInsensitive) == 0) return &f;
            return nullptr;
        }
        parts.removeFirst();
        for (auto &d : dir.dirs)
            if (d.name.compare(first, Qt::CaseInsensitive) == 0)
                return findFile(d, parts);
        return nullptr;
    }
};
