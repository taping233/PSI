#include "modsystem.h"

int main() {
    ModSystem sys;
    modsystem_init_auto(&sys, 256, 12345UL);
    modsystem_print(&sys);
    modsystem_free(&sys);
    return 0;
}

