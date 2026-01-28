# Cryptography Library 2026

Навчальна бібліотека класичних шифрів на C.

## Реалізовані шифри

- **Шифр Цезаря**
- **Шифр Трітеміуса**
- **Шифр Полібія**
- **Шифр Віженера**
- **Шифр одноразового блокноту (шифр Вернама)**
- **Шифри гамування**

## Встановлення
```bash
sudo apt install build-essential check pkg-config valgrind
```

## Компіляція
```bash
make               # Зібрати бібліотеку та demo
make test          # Запустити тести
make test-asan     # Перевірка memory leaks (AddressSanitizer)
make test-valgrind # Перевірка memory leaks (Valgrind)
make clean         # Очистити
```

## Використання
```bash
./cryptodemo  # Інтерактивне меню
```

## Структура
```
Cryptography-2026/
├── include/crypto/     # Headers
├── src/                # Реалізації
├── demo/               # Demo програма
├── tests/              # Unit тести
└── Makefile
```
