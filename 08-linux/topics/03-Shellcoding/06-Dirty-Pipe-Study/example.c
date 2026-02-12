/*
 * OBJECTIF  : Etude de cas de CVE-2022-0847 (Dirty Pipe)
 * PREREQUIS : Bases C, pipes Linux, splice(), page cache
 * COMPILE   : gcc -o example example.c
 *
 * Ce programme analyse le mecanisme de Dirty Pipe : comment une
 * faille dans la gestion du flag PIPE_BUF_FLAG_CAN_MERGE permettait
 * d'ecrire dans des fichiers en lecture seule, menant a une
 * escalade de privileges triviale (kernel 5.8 a 5.16.10).
 * Demonstration pedagogique uniquement - pas d'exploitation reelle.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <errno.h>

/*
 * Etape 1 : Contexte - le page cache Linux
 */
static void explain_page_cache(void) {
    printf("[*] Etape 1 : Le Page Cache Linux\n\n");

    printf("    ┌─────────────────────────────────────────────┐\n");
    printf("    │              PAGE CACHE                      │\n");
    printf("    │  Cache en RAM des pages lues depuis le disque│\n");
    printf("    │                                              │\n");
    printf("    │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐       │\n");
    printf("    │  │Page 0│ │Page 1│ │Page 2│ │Page 3│       │\n");
    printf("    │  │4096 B│ │4096 B│ │4096 B│ │4096 B│       │\n");
    printf("    │  └──────┘ └──────┘ └──────┘ └──────┘       │\n");
    printf("    │                                              │\n");
    printf("    │  Quand un fichier est lu :                   │\n");
    printf("    │  1. Le kernel le charge dans le page cache   │\n");
    printf("    │  2. Tous les processus partagent ces pages   │\n");
    printf("    │  3. Les pages sont synchronisees sur disque  │\n");
    printf("    └─────────────────────────────────────────────┘\n\n");

    printf("    Importance pour Dirty Pipe :\n");
    printf("    - splice() transfere des donnees SANS copie (zero-copy)\n");
    printf("    - Il referencie directement les pages du page cache\n");
    printf("    - Si on peut ecrire dans ces pages -> on modifie le fichier\n\n");
}

/*
 * Etape 2 : Pipes et splice()
 */
static void explain_pipes_and_splice(void) {
    printf("[*] Etape 2 : Pipes et splice()\n\n");

    printf("    Un pipe Linux est un buffer circulaire de pages :\n\n");

    printf("    pipe_buffer[] :\n");
    printf("    ┌────────┬────────┬────────┬────────┐\n");
    printf("    │ buf[0] │ buf[1] │ buf[2] │  ...   │\n");
    printf("    │  page  │  page  │  page  │        │\n");
    printf("    │  offset│  offset│  offset│        │\n");
    printf("    │  len   │  len   │  len   │        │\n");
    printf("    │  flags │  flags │  flags │        │\n");
    printf("    └────────┴────────┴────────┴────────┘\n\n");

    printf("    Le flag crucial : PIPE_BUF_FLAG_CAN_MERGE\n");
    printf("    - Quand ce flag est set, le kernel PEUT ajouter des donnees\n");
    printf("      a ce buffer au lieu d'en creer un nouveau\n\n");

    printf("    splice(fd_in, offset, pipe_fd, NULL, len, 0) :\n");
    printf("    - Transfere des donnees d'un fichier vers un pipe\n");
    printf("    - ZERO-COPY : la page du fichier est directement\n");
    printf("      referencee par le pipe_buffer\n");
    printf("    - Normalement, le flag CAN_MERGE est PAS set\n\n");
}

/*
 * Etape 3 : La faille - le flag CAN_MERGE persiste
 */
static void explain_vulnerability(void) {
    printf("[*] Etape 3 : La vulnerabilite CVE-2022-0847\n\n");

    printf("    Le bug (commit f6dd975583bd, kernel 5.8) :\n");
    printf("    Dans copy_page_to_iter_pipe() et push_pipe() :\n");
    printf("    -> Le champ 'flags' du pipe_buffer n'etait PAS initialise !\n\n");

    printf("    Sequence d'exploitation :\n\n");

    printf("    1. Creer un pipe\n");
    printf("       int pipe_fd[2];\n");
    printf("       pipe(pipe_fd);\n\n");

    printf("    2. Remplir TOUTES les pages du pipe (set CAN_MERGE)\n");
    printf("       for (int i = 0; i < pipe_size; i++)\n");
    printf("           write(pipe_fd[1], buf, page_size);\n\n");

    printf("    3. Vider le pipe (les pages sont liberees)\n");
    printf("       for (int i = 0; i < pipe_size; i++)\n");
    printf("           read(pipe_fd[0], buf, page_size);\n\n");

    printf("    4. splice() un fichier read-only dans le pipe\n");
    printf("       splice(fd_target, &offset, pipe_fd[1], NULL, 1, 0);\n");
    printf("       // BUG: le pipe_buffer herite du flag CAN_MERGE\n");
    printf("       // de l'ancienne page (etape 2) car flags non reinitialise\n\n");

    printf("    5. Ecrire dans le pipe -> ecrase la page du fichier !\n");
    printf("       write(pipe_fd[1], payload, payload_len);\n");
    printf("       // Le kernel voit CAN_MERGE et AJOUTE les donnees\n");
    printf("       // directement dans la page du page cache\n");
    printf("       // -> LE FICHIER EST MODIFIE meme s'il est read-only !\n\n");

    printf("    ┌─────────────────────────────────────────────┐\n");
    printf("    │  Resultat : ecriture arbitraire dans tout   │\n");
    printf("    │  fichier lisible, meme read-only, meme SUID │\n");
    printf("    │  -> Modifier /etc/passwd, SUID binaries...  │\n");
    printf("    └─────────────────────────────────────────────┘\n\n");
}

/*
 * Etape 4 : Demonstration des pipes (safe)
 */
static void demo_pipe_basics(void) {
    printf("[*] Etape 4 : Demonstration des pipes (sans exploitation)\n\n");

    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) {
        perror("    pipe");
        return;
    }

    /* Capacite du pipe */
    long pipe_size = fcntl(pipe_fd[1], F_GETPIPE_SZ);
    printf("    Pipe cree : read_fd=%d, write_fd=%d\n", pipe_fd[0], pipe_fd[1]);
    printf("    Capacite du pipe : %ld octets (%ld pages)\n\n",
           pipe_size, pipe_size / 4096);

    /* Ecrire et lire dans le pipe */
    const char *msg = "Hello from pipe!";
    ssize_t written = write(pipe_fd[1], msg, strlen(msg));
    printf("    Ecrit %zd octets dans le pipe\n", written);

    char buf[64] = {0};
    ssize_t rd = read(pipe_fd[0], buf, sizeof(buf) - 1);
    printf("    Lu %zd octets du pipe : \"%s\"\n\n", rd, buf);

    /* Remplir et vider pour montrer le recyclage */
    printf("    Remplissage du pipe (set CAN_MERGE sur toutes les pages) :\n");
    int pages = (int)(pipe_size / 4096);
    char page_buf[4096];
    memset(page_buf, 'A', sizeof(page_buf));

    int filled = 0;
    for (int i = 0; i < pages; i++) {
        if (write(pipe_fd[1], page_buf, sizeof(page_buf)) > 0)
            filled++;
    }
    printf("      %d pages ecrites\n", filled);

    int drained = 0;
    for (int i = 0; i < pages; i++) {
        if (read(pipe_fd[0], page_buf, sizeof(page_buf)) > 0)
            drained++;
    }
    printf("      %d pages lues (videes)\n", drained);
    printf("      [!] Dans le kernel vulnerable, les flags CAN_MERGE\n");
    printf("          persistent sur les pipe_buffers liberes\n\n");

    close(pipe_fd[0]);
    close(pipe_fd[1]);
}

/*
 * Etape 5 : Verifier la version du kernel
 */
static void check_kernel_version(void) {
    printf("[*] Etape 5 : Verification du kernel\n\n");

    struct utsname uts;
    if (uname(&uts) == 0) {
        printf("    Kernel actuel : %s %s\n", uts.sysname, uts.release);
        printf("    Architecture  : %s\n\n", uts.machine);
    }

    printf("    Versions affectees par Dirty Pipe :\n");
    printf("      - Linux >= 5.8   (introduction du bug)\n");
    printf("      - Linux <  5.16.11\n");
    printf("      - Linux <  5.15.25\n");
    printf("      - Linux <  5.10.102\n\n");

    /* Extraire la version majeure.mineure */
    int major = 0, minor = 0, patch = 0;
    if (sscanf(uts.release, "%d.%d.%d", &major, &minor, &patch) >= 2) {
        int vuln = 0;
        if (major == 5 && minor >= 8 && minor < 10)
            vuln = 1;
        else if (major == 5 && minor == 10 && patch < 102)
            vuln = 1;
        else if (major == 5 && minor >= 11 && minor < 15)
            vuln = 1;
        else if (major == 5 && minor == 15 && patch < 25)
            vuln = 1;
        else if (major == 5 && minor == 16 && patch < 11)
            vuln = 1;

        if (vuln)
            printf("    [!] Ce kernel POURRAIT etre vulnerable a Dirty Pipe\n\n");
        else
            printf("    [+] Ce kernel n'est probablement PAS vulnerable\n\n");
    }
}

/*
 * Etape 6 : Scenarios d'exploitation
 */
static void explain_exploitation(void) {
    printf("[*] Etape 6 : Scenarios d'exploitation\n\n");

    printf("    Scenario 1 : Modifier /etc/passwd\n");
    printf("    ─────────────────────────────────────\n");
    printf("    - Ecraser le hash root par un hash connu\n");
    printf("    - root:$known_hash:0:0:root:/root:/bin/bash\n");
    printf("    - su root avec le mot de passe connu\n\n");

    printf("    Scenario 2 : Modifier un binaire SUID\n");
    printf("    ─────────────────────────────────────\n");
    printf("    - Trouver un binaire SUID :\n");
    printf("      find / -perm -4000 -type f 2>/dev/null\n");
    printf("    - Injecter un shellcode dans l'ELF\n");
    printf("    - L'executer -> shell root\n\n");

    printf("    Scenario 3 : Modifier une cle SSH authorized_keys\n");
    printf("    ─────────────────────────────────────\n");
    printf("    - Ecrire sa cle publique dans /root/.ssh/authorized_keys\n");
    printf("    - ssh root@target\n\n");

    printf("    Contraintes :\n");
    printf("    - Le fichier cible doit etre LISIBLE (r--)\n");
    printf("    - On ne peut PAS ecrire a l'offset 0 (splice lit >= 1 octet)\n");
    printf("    - On ne peut PAS agrandir le fichier (page cache fixe)\n");
    printf("    - L'ecriture persiste en cache mais peut etre perdue au reboot\n\n");
}

/*
 * Etape 7 : Le correctif et les detections
 */
static void explain_fix_and_detection(void) {
    printf("[*] Etape 7 : Correctif et detection\n\n");

    printf("    Le correctif (commit 9d2231c5d74e) :\n");
    printf("    ─────────────────────────────────────\n");
    printf("    Dans copy_page_to_iter_pipe() :\n");
    printf("      buf->flags = 0;  // <- Initialiser le flag !\n\n");

    printf("    Dans push_pipe() :\n");
    printf("      buf->flags = 0;  // <- Meme chose\n\n");

    printf("    Une seule ligne de code corrige la faille !\n\n");

    printf("    Detection :\n");
    printf("    ─────────────────────────────────────\n");
    printf("    1. Version du kernel : uname -r\n");
    printf("    2. Audit des appels splice() suspects :\n");
    printf("       auditctl -a always,exit -F arch=b64 -S splice\n");
    printf("    3. Verifier l'integrite des fichiers :\n");
    printf("       aide --check, tripwire\n");
    printf("    4. Surveiller les modifications de /etc/passwd, /etc/shadow\n\n");

    printf("    Timeline :\n");
    printf("    ─────────────────────────────────────\n");
    printf("    2021-04  : Bug introduit dans Linux 5.8\n");
    printf("    2022-02-19 : Decouverte par Max Kellermann (CM4all)\n");
    printf("    2022-02-20 : Report au kernel team\n");
    printf("    2022-02-23 : Correctif pousse\n");
    printf("    2022-03-07 : Disclosure publique (CVE-2022-0847)\n\n");
}

/*
 * Etape 8 : Demonstration avec splice() (safe)
 */
static void demo_splice_concept(void) {
    printf("[*] Etape 8 : Concept de splice() (demonstration safe)\n\n");

    /* Creer un fichier temporaire */
    char tmpfile[] = "/tmp/dirty_pipe_demo_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        perror("    mkstemp");
        return;
    }

    const char *content = "ORIGINAL CONTENT - This is the file data\n";
    write(fd, content, strlen(content));
    printf("    Fichier cree : %s\n", tmpfile);
    printf("    Contenu      : %s", content);

    /* Creer un pipe et utiliser splice pour y transferer les donnees */
    int pipe_fd[2];
    if (pipe(pipe_fd) < 0) {
        perror("    pipe");
        close(fd);
        unlink(tmpfile);
        return;
    }

    /* splice : fichier -> pipe (zero-copy, reference la page cache) */
    loff_t offset = 0;
    ssize_t spliced = splice(fd, &offset, pipe_fd[1], NULL, strlen(content), 0);
    printf("    splice() : %zd octets transferes fichier -> pipe\n", spliced);

    /* Lire depuis le pipe */
    char buf[128] = {0};
    ssize_t rd = read(pipe_fd[0], buf, sizeof(buf) - 1);
    printf("    Lu du pipe : \"%s\"\n", buf);

    printf("    [i] Dans un kernel vulnerable, si CAN_MERGE est set,\n");
    printf("        un write() suivant modifierait la page du fichier\n\n");

    close(pipe_fd[0]);
    close(pipe_fd[1]);
    close(fd);
    unlink(tmpfile);
}

int main(void) {
    printf("[*] Demo : Dirty Pipe Study (CVE-2022-0847)\n\n");

    explain_page_cache();
    explain_pipes_and_splice();
    explain_vulnerability();
    demo_pipe_basics();
    check_kernel_version();
    explain_exploitation();
    explain_fix_and_detection();
    demo_splice_concept();

    printf("[+] Demo terminee avec succes\n");
    return 0;
}
