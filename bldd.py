import os
import sys
import argparse
from collections import defaultdict
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError

# Карта процессорных архитектур для ELF-заголовков
ARCH_MAP = {
    'EM_386': 'x86',
    'EM_X86_64': 'x86_64',
    'EM_ARM': 'armv7',
    'EM_AARCH64': 'aarch64'
}

def analyze_elf(file_path):
    """Считывает заголовок ELF и извлекает архитектуру и зависимости (DT_NEEDED)"""
    needed_libs = []
    arch = "Unknown"
    try:
        with open(file_path, 'rb') as f:
            elffile = ELFFile(f)
            elf_arch = elffile.header['e_machine']
            arch = ARCH_MAP.get(elf_arch, elf_arch)

            for section in elffile.iter_sections():
                if section.name == '.dynamic':
                    for tag in section.iter_tags():
                        if tag.entry.d_tag == 'DT_NEEDED':
                            val = tag.needed
                            if not isinstance(val, str):
                                val = val.decode('utf-8', errors='ignore')
                            needed_libs.append(val)
    except (ELFError, IOError, KeyError, AttributeError):
        return None, None
    return arch, needed_libs

def scan_directory(search_dir, target_archs):
    """Сканирует файлы и формирует структуру: { arch: { библиотека: [исполняемые_файлы] } }"""
    arch_to_libs = defaultdict(lambda: defaultdict(list))

    for root, _, files in os.walk(search_dir):
        for file in files:
            full_path = os.path.join(root, file)
            if os.path.islink(full_path):
                continue

            arch, libs = analyze_elf(full_path)
            if arch and libs:
                # Фильтрация по переданным в аргументы архитектурам
                if target_archs and arch not in target_archs:
                    continue
                for lib in libs:
                    arch_to_libs[arch][lib].append(full_path)
    return arch_to_libs

def generate_report(data, search_dir, output_path):
    """Записывает структурированный отчет в файл в строгом соответствии с ТЗ"""
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"Report on dynamic used libraries by ELF executables on {search_dir}\n\n")

        # Обходим по архитектурам
        for arch in sorted(data.keys()):
            f.write(f"---------- {arch} ----------\n")

            # Сортируем библиотеки внутри архитектуры по количеству исполняемых файлов (высокое -> низкое)
            sorted_libs = sorted(
                data[arch].items(),
                key=lambda x: len(x[1]),
                reverse=True
            )

            for lib, paths in sorted_libs:
                f.write(f"{lib} ({len(paths)} execs)\n")
                for path in sorted(paths):
                    f.write(f"        -> {path}\n")
            f.write("\n")

def main():
    parser = argparse.ArgumentParser(
        description="bldd (обратный ldd) — поиск исполняемых файлов, использующих общие библиотеки.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  python3 bldd.py -d /bin -o report.txt
  python3 bldd.py --dir /bin --arch x86_64 aarch64 --output report.txt
        """
    )
    parser.add_argument('-d', '--dir', required=True, metavar="ДИРЕКТОРИЯ", 
                        help="Директория для сканирования (например, /bin)")
    parser.add_argument('-o', '--output', default="bldd_report.txt", metavar="ФАЙЛ",
                        help="Путь для сохранения отчета (по умолчанию: bldd_report.txt)")
    parser.add_argument('-a', '--arch', nargs='+', choices=['x86', 'x86_64', 'armv7', 'aarch64'],
                        metavar="АРХИТЕКТУРА",
                        help="Фильтр по архитектурам: x86, x86_64, armv7, aarch64 (можно несколько через пробел)")

    # Если пользователь запустил программу вообще без флагов
    if len(sys.argv) == 1:
        print("[!] Ошибка: Не указаны обязательные параметры.\n", file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    print(f"[*] Сканирование директории: {args.dir}")
    result_data = scan_directory(args.dir, args.arch)

    print(f"[*] Генерация отчета в: {args.output}")
    generate_report(result_data, args.dir, args.output)
    print("[+] Готово!")

if __name__ == '__main__':
    main()

