def encrypt_ceasar(word, key):
    result = ''
    for lett, k in zip(word, key):
        shift = dct[k.lower()]
        if 'А' <= lett <= 'Я':
            base = ord('А')
            nev_lett = base + 1 + (ord(lett) - base + shift) % 32
        elif 'а' <= lett <= 'я':
            base = ord('а')
            nev_lett = base + 1 + (ord(lett) - base + shift) % 32
        else:
            result += lett
            continue
        result += chr(nev_lett)
    return result

def decrypt_ceasar(word, key):
    result = ''
    for lett, k in zip(word, key):
        shift = dct[k.lower()]
        if 'А' <= lett <= 'Я':
            base = ord('А')
            nev_lett = base - 1 + (ord(lett) - base - shift) % 32
        elif 'а' <= lett <= 'я':
            base = ord('а')
            nev_lett = base - 1 + (ord(lett) - base - shift) % 32
        else:
            result += lett
            continue
        result += chr(nev_lett)
    return result

def adeq(word, key):
    size_word = len(word)
    while len(key) < size_word:
        key += key
    return key[:size_word]

dct = {}
start, end = ord('а'), ord('я') + 1
for i in range(start, end):
    dct[chr(i)] = i - start

print('Что будем делать? (0 - зашифровывать; 1 - расшифровывать)')
act = int(input())
word = input('Введите слово: ')
key = input('ключ: ')
nev_key = adeq(word, key)
if act == 0:
    print('Зашифрованное слово:', encrypt_ceasar(word, nev_key))
else:
    print('Расшифрованное слово:', decrypt_ceasar(word, nev_key))