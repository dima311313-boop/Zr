#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QTextStream>
#include "ngdecrypt.h"
#include "rpfdecrypt.h"
#include "rpfarchive.h"
#include <windows.h>

static const QString KEYS_DIR   = "C:/Users/Admin/Desktop/GTAVKeys";
static const QString AES_KEY    = "C:/Users/Admin/Desktop/GTAVKeys/gtav_aes_key.dat";

// ============================================================
// Отрисовка дерева в консоль
// ============================================================
static QTextStream out(stdout);

void printTree(const RpfDirNode &dir, const QString &prefix = "", bool isLast = true) {
    // Заголовок директории
    QString connector = isLast ? "└── " : "├── ";
    if (prefix.isEmpty())
        out << "[ " << dir.name << " ]\n";
    else
        out << prefix << connector << "[ " << dir.name << " ]\n";

    QString childPrefix = prefix + (isLast ? "    " : "│   ");

    int totalChildren = dir.dirs.size() + dir.files.size();
    int idx = 0;

    // Сначала директории
    for (int i = 0; i < dir.dirs.size(); i++) {
        bool last = (idx == totalChildren - 1);
        printTree(dir.dirs[i], childPrefix, last);
        idx++;
    }
    // Потом файлы
    for (int i = 0; i < dir.files.size(); i++) {
        bool last = (idx == totalChildren - 1);
        QString fc = last ? "└── " : "├── ";
        out << childPrefix << fc << dir.files[i].name;
        if (dir.files[i].dataSize > 0) {
            // Размер в читаемом виде
            uint32_t sz = dir.files[i].dataSize;
            if (sz < 1024)
                out << "  (" << sz << " B)";
            else if (sz < 1024*1024)
                out << "  (" << QString::number(sz/1024.0, 'f', 1) << " KB)";
            else
                out << "  (" << QString::number(sz/1024.0/1024.0, 'f', 2) << " MB)";
        }
        out << "\n";
        idx++;
    }
}

void printHelp() {
    out << "\n";
    out << "  Zr_Console — RPF Reader for GTA V\n";
    out << "  ══════════════════════════════════\n\n";
    out << "  Usage:\n";
    out << "    zr_console -list    <file.rpf>              List contents\n";
    out << "    zr_console -info    <file.rpf>              Show RPF info\n";
    out << "    zr_console -extract <file.rpf> -out <dir>   Extract all files\n";
    out << "    zr_console -extract <file.rpf> <inner/path> -out <dir>  Extract one file\n\n";
    out << "  Keys directory: " << KEYS_DIR << "\n\n";
}

// ============================================================
// Команды
// ============================================================
void cmdInfo(RpfArchive &rpf) {
    out << "\n";
    out << "  ┌─────────────────────────────────────┐\n";
    out << "  │  RPF Info: " << QFileInfo(rpf.path).fileName() << "\n";
    out << "  ├─────────────────────────────────────┤\n";
    out << "  │  Entries:    " << rpf.header.entryCount << "\n";
    out << "  │  Names size: " << rpf.header.namesLength << " bytes\n";
    out << "  │  Encryption: ";
    uint8_t enc = rpf.header.encryptionType & 0xFF;
    if (enc == 0xFF) out << "NG (entries) + AES-256 (data)\n";
    else if (enc == 0xFE) out << "Open (unencrypted)\n";
    else out << "None\n";
    if (rpf.ngKeyIndex >= 0)
        out << "  │  NG Key idx: " << rpf.ngKeyIndex << "\n";
    out << "  └─────────────────────────────────────┘\n\n";
}

void cmdList(RpfArchive &rpf) {
    cmdInfo(rpf);
    printTree(rpf.root);
    out << "\n";
}

void extractAll(const RpfDirNode &dir, const QString &basePath, RpfArchive &rpf, int &count) {
    QDir().mkpath(basePath);
    for (const auto &file : dir.files) {
        QByteArray data = rpf.readFileData(const_cast<RpfFileNode&>(file));
        QFile f(basePath + "/" + file.name);
        if (f.open(QIODevice::WriteOnly)) {
            f.write(data);
            f.close();
            out << "  Extracted: " << file.name << "  (" << data.size() << " bytes)\n";
            count++;
        }
    }
    for (const auto &subdir : dir.dirs)
        extractAll(subdir, basePath + "/" + subdir.name, rpf, count);
}

void cmdExtract(RpfArchive &rpf, const QString &innerPath, const QString &outDir) {
    QDir().mkpath(outDir);
    if (innerPath.isEmpty()) {
        // Извлечь всё
        out << "  Extracting all to: " << outDir << "\n\n";
        int count = 0;
        extractAll(rpf.root, outDir, rpf, count);
        out << "\n  Done! " << count << " files extracted.\n\n";
    } else {
        // Извлечь конкретный файл
        QByteArray data = rpf.extractFile(innerPath);
        if (data.isEmpty()) { out << "  ERROR: file not found: " << innerPath << "\n"; return; }
        QString outFile = outDir + "/" + QFileInfo(innerPath).fileName();
        QFile f(outFile);
        if (f.open(QIODevice::WriteOnly)) { f.write(data); f.close(); }
        out << "  Extracted: " << outFile << "  (" << data.size() << " bytes)\n\n";
    }
}

// ============================================================
// main
// ============================================================
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    #ifdef Q_OS_WIN
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #endif

    // Загружаем ключи
    if (!loadNgKeys(KEYS_DIR)) { qWarning() << "Failed to load NG keys from" << KEYS_DIR; return 1; }
    if (!loadAesKey(AES_KEY))  { qWarning() << "Failed to load AES key from" << AES_KEY;  return 1; }

    QStringList args = app.arguments();
    args.removeFirst(); // убираем имя exe

    if (args.isEmpty() || args.contains("-h") || args.contains("--help")) {
        printHelp();
        return 0;
    }

    // Парсим аргументы
    QString cmd      = args.value(0);
    QString rpfPath  = args.value(1);
    QString outDir   = "";
    QString innerPath = "";

    // Ищем -out
    int outIdx = args.indexOf("-out");
    if (outIdx >= 0) outDir = args.value(outIdx + 1);

    // Для extract может быть внутренний путь
    if (cmd == "-extract" && args.size() > 2 && !args.value(2).startsWith("-"))
        innerPath = args.value(2);

    if (rpfPath.isEmpty()) { printHelp(); return 1; }

    // Открываем RPF
    out << "\n  Loading: " << rpfPath << " ...\n";
    RpfArchive rpf;
    if (!rpf.open(rpfPath)) { out << "  ERROR: Failed to open RPF\n\n"; return 1; }
    out << "  OK! " << rpf.header.entryCount << " entries, key=" << rpf.ngKeyIndex << "\n\n";

    if      (cmd == "-list")    cmdList(rpf);
    else if (cmd == "-info")    cmdInfo(rpf);
    else if (cmd == "-extract") cmdExtract(rpf, innerPath, outDir.isEmpty() ? "output" : outDir);
    else { out << "  Unknown command: " << cmd << "\n"; printHelp(); }

    return 0;
}
