#pragma once
#include <QDebug>
#include <QFile>
#include "rpfreader.h"

bool createTestRpf(const QString &path) {
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly)) {
        qWarning() << "Cannot create file:" << path;
        return false;
    }

    // --- Данные которые положим в файлы ---
    QByteArray helloData = "Hello from RPF! This is hello.txt";
    QByteArray binData   = "\x01\x02\x03\x04\x05\x06\x07\x08";

    // --- Блок имён ---
    QByteArray namesBlock;

    uint32_t offsetRoot  = namesBlock.size();
    namesBlock.append("root");      namesBlock.append('\0');

    uint32_t offsetHello = namesBlock.size();
    namesBlock.append("hello.txt"); namesBlock.append('\0');

    uint32_t offsetData  = namesBlock.size();
    namesBlock.append("data.bin");  namesBlock.append('\0');

    while (namesBlock.size() % 16 != 0)
        namesBlock.append('\0');

    // --- Считаем где будут лежать данные файлов ---
    // Данные начинаются после: заголовок + entries + блок имён
    uint32_t dataStart = sizeof(RpfHeader)
                         + 3 * sizeof(RpfFileEntry)
                         + namesBlock.size();

    uint32_t helloOffset = dataStart;
    uint32_t binOffset   = dataStart + helloData.size();

    // --- Заголовок ---
    RpfHeader header;
    header.magic          = RPF7_MAGIC;
    header.entryCount     = 3;
    header.namesLength    = namesBlock.size();
    header.encryptionType = 0x00;
    file.write(reinterpret_cast<char*>(&header), sizeof(RpfHeader));

    // --- Entries ---
    RpfDirectoryEntry root;
    root.nameOffset = offsetRoot;
    root.marker     = RPF_DIR_MARKER;
    root.entryIndex = 1;
    root.entryCount = 2;
    file.write(reinterpret_cast<char*>(&root), sizeof(root));

    RpfFileEntry hello;
    hello.nameOffset = offsetHello;
    hello.dataOffset = helloOffset;  // <- теперь указывает на реальные данные
    hello.dataSize   = helloData.size();
    hello.flags      = 0;
    file.write(reinterpret_cast<char*>(&hello), sizeof(hello));

    RpfFileEntry data;
    data.nameOffset = offsetData;
    data.dataOffset = binOffset;     // <- и этот тоже
    data.dataSize   = binData.size();
    data.flags      = 0;
    file.write(reinterpret_cast<char*>(&data), sizeof(data));

    // --- Блок имён ---
    file.write(namesBlock);

    // --- Сами данные файлов ---
    file.write(helloData);
    file.write(binData);

    qDebug() << "Test RPF created:" << path;
    return true;
}
