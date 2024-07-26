gcc -Wall -Wextra -std="c11" -o x64_emu ./src/main.c -lncurses
read -p "Press any key to execute..."
./x64_emu
