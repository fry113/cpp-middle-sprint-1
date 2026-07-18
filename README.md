# CryptoGuard

CryptoGuard - C++ библиотека для работы с файлами:

- шифрование и расшифровка (AES-256-CBC, OpenSSL EVP),
- вычисление контрольной суммы (SHA-256),
- простой CLI-инструмент поверх библиотечного API.

Проект собирается через Conan + CMake и включает unit-тесты на GoogleTest.

## Возможности

- Библиотечный API в пространстве имен `CryptoGuard`.
- Шифрование файлов с паролем.
- Расшифровка файлов с тем же паролем.
- Расчет SHA-256 для входного потока.
- CLI с командами `encrypt`, `decrypt`, `checksum`.

## Структура проекта

- `include/crypto_guard_ctx.h` - публичный интерфейс библиотеки.
- `include/cmd_options.h` - интерфейс разбора параметров CLI.
- `src/crypto_guard_ctx.cpp` - реализация криптоопераций.
- `src/cmd_options.cpp` - реализация парсинга аргументов.
- `src/main.cpp` - консольное приложение `CryptoGuard`.
- `tests/` - unit-тесты.

## Требования

- C++23 компилятор (GCC/Clang).
- Conan 2.x.
- CMake 3.30+.

Основные зависимости:

- OpenSSL
- Boost.Program_options
- GTest

## Сборка

### Вариант 1: через задачи VS Code

Запустите одну из задач:

- `GCC: Build Debug`
- `GCC: Build Release`

### Вариант 2: из терминала

```bash
mkdir -p build
cd build
conan build -b missing -s build_type=Debug ..
```

Для релизной конфигурации:

```bash
conan build -b missing -s build_type=Release ..
```

После сборки в директории `build/` будут доступны:

- `CryptoGuard` - CLI-приложение,
- `unit_tests` - тесты.

## Использование библиотеки

Публичный API класса `CryptoGuard::CryptoGuardCtx`:

- `EncryptFile(std::iostream&, std::iostream&, std::string_view password)`
- `DecryptFile(std::iostream&, std::iostream&, std::string_view password)`
- `CalculateChecksum(std::iostream&) -> std::string`

Пример:

```cpp
#include "crypto_guard_ctx.h"
#include <sstream>

int main() {
    CryptoGuard::CryptoGuardCtx ctx;

    std::stringstream plain;
    std::stringstream encrypted;
    std::stringstream decrypted;

    plain << "hello";
    ctx.EncryptFile(plain, encrypted, "pass123");
    ctx.DecryptFile(encrypted, decrypted, "pass123");

    auto checksum = ctx.CalculateChecksum(decrypted);
    (void)checksum;
}
```

## Использование CLI

Справка:

```bash
./build/CryptoGuard --help
```

Аргументы:

- `-c, --command` - команда: `encrypt`, `decrypt`, `checksum`
- `-i, --input` - входной файл (по умолчанию `input.txt`)
- `-o, --output` - выходной файл (по умолчанию `output.txt`)
- `-p, --password` - пароль (по умолчанию `testpwd`)

Примеры:

```bash
echo "Hello OpenSSL crypto world!" > input.txt

./build/CryptoGuard -c encrypt  -i input.txt     -o encrypted.bin -p 1234
./build/CryptoGuard -c decrypt  -i encrypted.bin -o decrypted.txt -p 1234
./build/CryptoGuard -c checksum -i input.txt
./build/CryptoGuard -c checksum -i decrypted.txt
```

## Запуск тестов

```bash
./build/unit_tests
```

## Важные замечания

- Проект учебный и ориентирован на демонстрацию архитектуры и API.
- Сейчас ключ/IV детерминированно выводятся из пароля и фиксированной соли.
- Для production-использования требуется усиление криптографической схемы (случайная соль/IV, KDF с большим числом итераций, хранение метаданных шифрования).