/*
 * OBJECTIF  : Jitter et sleep variable pour eviter la detection par pattern
 * PREREQUIS : C2 basics, statistiques
 * COMPILE   : cl example.c /Fe:example.exe
 *
 * Un C2 qui callback a intervalles fixes est trivial a detecter.
 * Le jitter ajoute de l'aleatoire pour casser les patterns temporels.
 */

#include <windows.h>
#include <stdio.h>
#include <math.h>

/* Calculer le sleep avec jitter */
DWORD calc_sleep_jitter(DWORD base_ms, int jitter_pct) {
    if (jitter_pct <= 0 || jitter_pct > 100)
        return base_ms;
    DWORD range = (base_ms * jitter_pct) / 100;
    DWORD offset = (DWORD)(rand() % (range * 2 + 1));
    DWORD result = base_ms - range + offset;
    return result > 0 ? result : 1;
}

void demo_fixed_sleep(void) {
    printf("[1] Sleep fixe (facilement detectable)\n\n");
    DWORD sleep_ms = 5000;
    int i;
    printf("    Intervalle fixe = %lu ms\n", sleep_ms);
    printf("    Callbacks : ");
    for (i = 0; i < 8; i++)
        printf("%lu ", sleep_ms);
    printf("\n");
    printf("    -> Pattern regulier : detection triviale par analyse statistique\n");
    printf("    -> Ecart-type = 0, coefficient de variation = 0%%\n\n");
}

void demo_jitter_sleep(void) {
    printf("[2] Sleep avec jitter (randomisation)\n\n");

    srand(GetTickCount());
    DWORD base = 5000;
    int jitters[] = {10, 25, 50};
    int j;

    for (j = 0; j < 3; j++) {
        int pct = jitters[j];
        printf("    Jitter %d%% (base=%lu ms) :\n    ", pct, base);

        double sum = 0, sum2 = 0;
        int i;
        for (i = 0; i < 10; i++) {
            DWORD val = calc_sleep_jitter(base, pct);
            printf("%lu ", val);
            sum += val;
            sum2 += (double)val * val;
        }

        double mean = sum / 10;
        double variance = (sum2 / 10) - (mean * mean);
        double stddev = sqrt(variance);
        printf("\n    Moyenne=%.0f  Ecart-type=%.0f  CV=%.1f%%\n\n",
               mean, stddev, (stddev / mean) * 100);
    }
}

void demo_sleep_patterns(void) {
    printf("[3] Patterns de sleep avances\n\n");

    printf("    a) Working hours only :\n");
    printf("       - Callback uniquement 08h-18h lun-ven\n");
    printf("       - Reduit le risque d'alertes hors heures\n\n");

    printf("    b) Gaussian jitter :\n");
    printf("       - Distribution normale au lieu d'uniforme\n");
    printf("       - Plus realiste (ressemble a du trafic humain)\n\n");

    /* Demo distribution gaussienne simple (Box-Muller) */
    printf("    Demo Gaussian (base=5000ms, sigma=1000ms) :\n    ");
    srand(GetTickCount() ^ 0xDEAD);
    int i;
    for (i = 0; i < 8; i++) {
        double u1 = (double)(rand() % 10000 + 1) / 10001.0;
        double u2 = (double)(rand() % 10000 + 1) / 10001.0;
        double z = sqrt(-2.0 * log(u1)) * cos(2.0 * 3.14159265 * u2);
        DWORD val = (DWORD)(5000 + z * 1000);
        if (val < 1000) val = 1000;
        printf("%lu ", val);
    }
    printf("\n\n");

    printf("    c) Adaptive sleep :\n");
    printf("       - Si activite reseau elevee -> sleep court\n");
    printf("       - Si heures creuses -> sleep long\n");
    printf("       - Si detection suspectee -> sleep tres long\n\n");
}

void demo_detection(void) {
    printf("[4] Detection du jitter\n\n");
    printf("    Indicateurs pour les defenseurs :\n");
    printf("    - Coefficient de variation trop bas = suspect\n");
    printf("    - Distribution uniforme vs trafic reel\n");
    printf("    - Connexions a heures regulieres meme avec jitter\n");
    printf("    - Volume de donnees constant a chaque callback\n\n");
    printf("    Outils de detection :\n");
    printf("    - RITA (Real Intelligence Threat Analytics)\n");
    printf("    - AC-Hunter : analyse de beaconing\n");
    printf("    - Zeek scripts pour detecter les patterns\n\n");

    /* Simuler une analyse de beaconing */
    printf("    Analyse de 10 intervalles :\n");
    srand(42);
    DWORD intervals[10];
    double sum = 0;
    int i;
    for (i = 0; i < 10; i++) {
        intervals[i] = calc_sleep_jitter(5000, 25);
        sum += intervals[i];
    }
    double mean = sum / 10;
    double var = 0;
    for (i = 0; i < 10; i++) {
        double d = intervals[i] - mean;
        var += d * d;
    }
    var /= 10;
    double stddev = sqrt(var);
    double cv = (stddev / mean) * 100;

    printf("    Moyenne: %.0f ms, Ecart-type: %.0f ms, CV: %.1f%%\n", mean, stddev, cv);
    if (cv < 5)
        printf("    -> ALERTE : CV < 5%%, beaconing probable!\n\n");
    else if (cv < 15)
        printf("    -> SUSPECT : CV < 15%%, possible beaconing avec jitter\n\n");
    else
        printf("    -> NORMAL : CV >= 15%%, difficilement distinguable\n\n");
}

int main(void) {
    printf("[*] Demo : Jitter et Sleep pour C2\n");
    printf("[*] ==========================================\n\n");
    demo_fixed_sleep();
    demo_jitter_sleep();
    demo_sleep_patterns();
    demo_detection();
    printf("[+] Exemple termine avec succes\n");
    return 0;
}
