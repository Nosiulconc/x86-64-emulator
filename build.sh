gcc -Wall -Wextra -Wno-incompatible-pointer-types -Wno-unused-parameter -Wno-unused-variable -Wno-return-type -Wno-implicit-fallthrough -std="c11" -o x64_emu ./src/main.c -lncurses -lSDL2 -pthread -lm
read -p "Press any key to execute..."
./x64_emu
