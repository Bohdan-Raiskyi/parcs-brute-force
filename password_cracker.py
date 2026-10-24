"""
Паралельний Brute-force для зламу паролів на базі системи PARCS-Python.

Один файл містить обидва алгоритми:
  * ПОСЛІДОВНИЙ   — функція sequential_crack() та CLI-команда 'seq';
  * ПАРАЛЕЛЬНИЙ   — клас Solver (модель map/reduce системи PARCS).

Як це працює в хмарі (PARCS-Python):
  1. master- і worker-вузли підняті як Docker-контейнери на хмарних ВМ;
  2. цей файл (рішення) + вхідний файл завантажуються через веб-інтерфейс
     master-вузла (http://MASTER_IP:8080  ->  Add Job);
  3. master розбиває простір паролів на діапазони й роздає їх воркерам;
     кожен воркер віддалено (Pyro4 RMI) виконує метод crack_range() над
     своїм діапазоном; master збирає результати (reduce) і пише output-файл;
  4. результат завантажується з веб-інтерфейсу.

Формат ВХІДНОГО файлу (рівно 4 рядки):
    <algorithm>     алгоритм гешування: md5 | sha1 | sha256 ...
    <target_hash>   шістнадцятковий геш шуканого пароля
    <charset>       набір символів, напр. abcdefghijklmnopqrstuvwxyz0123456789
    <max_length>    максимальна довжина пароля, напр. 4

Приклад створення гешу для тесту:
    python password_cracker.py hash md5 ab12
"""
from __future__ import print_function, division

import hashlib
import sys
import time

# У контейнері PARCS бібліотека Pyro4 присутня (саме вона реалізує RMI).
# Для локального запуску ПОСЛІДОВНОГО алгоритму вона не потрібна —
# підміняємо декоратор @expose порожньою заглушкою.
try:
    from Pyro4 import expose
except ImportError:
    def expose(func):
        return func


class Solver(object):
    """Паралельний розв'язувач у термінах PARCS (map/reduce)."""

    # ------------------------------------------------------------------ #
    #  Контракт PARCS: конструктор (workers, input_file, output_file)    #
    #  та метод solve(), який master викликає для старту задачі.          #
    # ------------------------------------------------------------------ #
    def __init__(self, workers=None, input_file_name=None, output_file_name=None):
        self.workers = workers
        self.input_file_name = input_file_name
        self.output_file_name = output_file_name

    def solve(self):
        algorithm, target, charset, max_length = self.read_input()
        n = len(self.workers)
        _, _, total = Solver.layout(charset, max_length)
        print("Workers: %d; keyspace size: %d" % (n, total))

        step = total // n
        start = time.time()

        # ---- MAP: кожному воркеру — свій неперервний діапазон індексів ----
        mapped = []
        for i in range(n):
            lo = i * step
            hi = total if i == n - 1 else (i + 1) * step
            print("map worker %d -> [%d, %d)" % (i, lo, hi))
            mapped.append(self.workers[i].crack_range(
                algorithm, target, charset, max_length, str(lo), str(hi)))

        # ---- REDUCE: перший непорожній результат і є знайдений пароль ----
        password = self.myreduce(mapped)
        elapsed = time.time() - start

        self.write_output(password, target, total, n, elapsed)
        print("Job finished in %.3f s; result: %s"
              % (elapsed, password if password else "NOT FOUND"))

    # ------------------------------------------------------------------ #
    #  Обчислювальний модуль воркера (виконується віддалено, @expose).   #
    #  Перебирає свій діапазон індексів простору паролів.                #
    # ------------------------------------------------------------------ #
    @staticmethod
    @expose
    def crack_range(algorithm, target, charset, max_length, start_index, end_index):
        start_index = int(start_index)
        end_index = int(end_index)
        base = len(charset)
        sizes, starts, _ = Solver.layout(charset, max_length)

        # Індекс -> кандидат трактуємо як "одометр" у системі числення base.
        # Спочатку знаходимо довжину L та розряди, що відповідають start_index.
        i = start_index
        length = 1
        while length <= max_length and \
                not (starts[length - 1] <= i < starts[length - 1] + sizes[length - 1]):
            length += 1
        local = i - starts[length - 1]
        digits = [0] * length
        for pos in range(length - 1, -1, -1):
            digits[pos] = local % base
            local //= base

        remaining = end_index - start_index
        while remaining > 0:
            candidate = ''.join([charset[d] for d in digits])
            if Solver.digest(algorithm, candidate) == target:
                return candidate
            # інкремент одометра в межах поточної довжини
            pos = length - 1
            while pos >= 0:
                digits[pos] += 1
                if digits[pos] < base:
                    break
                digits[pos] = 0
                pos -= 1
            if pos < 0:                 # переповнення -> наступна довжина
                length += 1
                if length > max_length:
                    break
                digits = [0] * length
            remaining -= 1
        return ''                       # у цьому діапазоні пароль не знайдено

    @staticmethod
    @expose
    def myreduce(mapped):
        for future in mapped:
            value = future.value        # Pyro4 future -> результат воркера
            if value:
                return value
        return ''

    # ------------------------------------------------------------------ #
    #  Чисті допоміжні функції (спільні для послідовного й паралельного).#
    # ------------------------------------------------------------------ #
    @staticmethod
    def layout(charset, max_length):
        """Розкладка простору паролів довжин 1..max_length.

        Повертає (sizes, starts, total):
          sizes[L-1]  — кількість паролів довжини L  (base**L);
          starts[L-1] — глобальний індекс першого пароля довжини L;
          total       — загальний розмір простору.
        """
        base = len(charset)
        sizes, starts, acc = [], [], 0
        for length in range(1, max_length + 1):
            size = base ** length
            starts.append(acc)
            sizes.append(size)
            acc += size
        return sizes, starts, acc

    @staticmethod
    def digest(algorithm, text):
        h = hashlib.new(algorithm)
        h.update(text.encode('ascii'))
        return h.hexdigest()

    # ------------------------------------------------------------------ #
    #  Введення / виведення                                              #
    # ------------------------------------------------------------------ #
    def read_input(self):
        f = open(self.input_file_name, 'r')
        algorithm = f.readline().strip()
        target = f.readline().strip()
        charset = f.readline().strip()
        max_length = int(f.readline().strip())
        f.close()
        return algorithm, target, charset, max_length

    def write_output(self, password, target, total, workers, elapsed):
        f = open(self.output_file_name, 'w')
        if password:
            f.write("FOUND\n")
            f.write("password: %s\n" % password)
        else:
            f.write("NOT FOUND\n")
        f.write("target_hash: %s\n" % target)
        f.write("keyspace: %d\n" % total)
        f.write("workers: %d\n" % workers)
        f.write("elapsed_sec: %.3f\n" % elapsed)
        f.close()


# ====================================================================== #
#  ПОСЛІДОВНИЙ алгоритм: перебір усього простору одним процесом.          #
#  Повторно використовує той самий обчислювальний модуль crack_range,    #
#  тому результати послідовного і паралельного збігаються за побудовою.  #
# ====================================================================== #
def sequential_crack(algorithm, target, charset, max_length):
    _, _, total = Solver.layout(charset, max_length)
    return Solver.crack_range(algorithm, target, charset, max_length, 0, total)


# ------------------------------- CLI ---------------------------------- #
def _usage():
    print("Використання:")
    print("  python password_cracker.py hash <algorithm> <plaintext>")
    print("  python password_cracker.py seq  <input_file> [output_file]")


def _main(argv):
    if len(argv) >= 4 and argv[1] == 'hash':
        print(Solver.digest(argv[2], argv[3]))
        return 0

    if len(argv) >= 3 and argv[1] == 'seq':
        f = open(argv[2], 'r')
        algorithm = f.readline().strip()
        target = f.readline().strip()
        charset = f.readline().strip()
        max_length = int(f.readline().strip())
        f.close()

        _, _, total = Solver.layout(charset, max_length)
        print("Sequential brute-force; keyspace size: %d" % total)
        start = time.time()
        password = sequential_crack(algorithm, target, charset, max_length)
        elapsed = time.time() - start
        print("Result: %s" % (password if password else "NOT FOUND"))
        print("elapsed: %.3f s" % elapsed)

        if len(argv) >= 4:
            out = open(argv[3], 'w')
            out.write((password if password else "NOT FOUND") + "\n")
            out.write("elapsed_sec: %.3f\n" % elapsed)
            out.close()
        return 0

    _usage()
    return 1


if __name__ == '__main__':
    sys.exit(_main(sys.argv))
