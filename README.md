# nop-virus

Исследование вирусных и антивирусных технологий. Используется TASM для Win32 (Windows 95/98).

Содержание:

* запаковка/распаковка вирусного кода методом XOR, в качестве ключа - текущий адрес в памяти (обход эвристического анализатора антивируса): arch.asm, infect.crypt.asm
* использование хэша функций, вместо открытых имен (сокрытие вызываемых внешних функций в коде): gethash.asm
* перехват вызова функций и выполнение собственного кода (резидентный код): hookapi.asm
* заражение исполняемых файлов путем подмены адреса в PE-заголовке, выполнение внедренного кода и возврат управления оригинальному коду: infect.asm, infect.jmp.asm
* запись кода в межсекционное пространство исполняемых файлов и сборка фрагментов кода при запуске приложения: infect.mezo.asm, infect.sec.asm
* обединение полученных результатов: nop.asm

Вирус не представляет опасности (заражение и все последующие операции производятся лишь с одним файлом C:\TEST.EXE) и должен быть использован лишь для ознакомления с описанными технологиями.

