#!/usr/bin/env python3
"""
Quiz Runner - Auto-evaluation pour le cours C Maldev Journey

Usage:
    python quiz-runner.py <chemin/vers/quiz.json>

Exemple:
    python quiz-runner.py ../Learning-Path/Phase-1-Foundations/Week-01-C-Absolute-Basics/quiz.json
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime

# =============================================================================
# COULEURS TERMINAL
# =============================================================================

class Colors:
    """Codes ANSI pour les couleurs (fonctionne sur Windows 10+ et Linux/Mac)"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

def init_colors():
    """Active les couleurs ANSI sur Windows"""
    if os.name == 'nt':
        os.system('color')

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def clear_screen():
    """Efface l'ecran"""
    os.system('cls' if os.name == 'nt' else 'clear')

def load_quiz(path: str) -> dict:
    """Charge le fichier quiz.json"""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def print_header(title: str):
    """Affiche un header formate"""
    width = 50
    print()
    print(f"{Colors.BOLD}{'=' * width}{Colors.END}")
    print(f"{Colors.BOLD}  {title}{Colors.END}")
    print(f"{Colors.BOLD}{'=' * width}{Colors.END}")
    print()

def print_code_block(code: str):
    """Affiche un bloc de code formate"""
    print(f"{Colors.YELLOW}")
    for line in code.split('\n'):
        print(f"    {line}")
    print(f"{Colors.END}")

# =============================================================================
# AFFICHAGE DES QUESTIONS
# =============================================================================

def display_question(q: dict, num: int, total: int):
    """Affiche une question formatee"""
    clear_screen()

    # Header avec numero
    print(f"\n{Colors.BOLD}Question {num}/{total}{Colors.END}")
    print(f"{Colors.CYAN}[{q['type'].upper()}]{Colors.END}")
    print()

    # Question (avec code si present)
    question_text = q['question']

    if '\n' in question_text:
        # Question avec code
        lines = question_text.split('\n')
        print(lines[0])  # Premiere ligne = question
        print()
        # Reste = code
        print_code_block('\n'.join(lines[1:]))
    else:
        print(question_text)

    print()

    # Options
    for i, opt in enumerate(q['options']):
        print(f"  [{i+1}] {opt}")

    print()

# =============================================================================
# EXECUTION DU QUIZ
# =============================================================================

def run_quiz(quiz: dict) -> tuple:
    """Execute le quiz et retourne (passed, score)"""

    clear_screen()
    print_header(f"QUIZ: {quiz['title']}")

    print(f"  {Colors.DIM}Score minimum pour valider: {quiz['passing_score']}/10{Colors.END}")
    print()

    input(f"  Appuie sur {Colors.BOLD}ENTREE{Colors.END} pour commencer...")

    score = 0
    total = len(quiz['questions'])
    wrong_answers = []

    for i, q in enumerate(quiz['questions'], 1):
        display_question(q, i, total)

        # Lire la reponse
        while True:
            try:
                answer = input(f"{Colors.BOLD}Ta reponse (1-{len(q['options'])}): {Colors.END}")
                answer = int(answer)

                if 1 <= answer <= len(q['options']):
                    break
                else:
                    print(f"{Colors.RED}  Entre un nombre entre 1 et {len(q['options'])}{Colors.END}")
            except ValueError:
                print(f"{Colors.RED}  Entre un nombre valide{Colors.END}")

        # Verifier la reponse (JSON est 0-indexed, user est 1-indexed)
        if answer - 1 == q['answer']:
            print()
            print(f"{Colors.GREEN}  ✓ CORRECT !{Colors.END}")
            score += 1
        else:
            print()
            print(f"{Colors.RED}  ✗ INCORRECT{Colors.END}")
            correct_answer = q['options'][q['answer']]
            print(f"  Bonne reponse: [{q['answer']+1}] {correct_answer}")

            wrong_answers.append({
                'num': i,
                'question': q['question'].split('\n')[0][:50],
                'your_answer': q['options'][answer-1],
                'correct': correct_answer,
                'explanation': q['explanation']
            })

        print()
        print(f"{Colors.DIM}  Explication: {q['explanation']}{Colors.END}")
        print()

        if i < total:
            input(f"  Appuie sur {Colors.BOLD}ENTREE{Colors.END} pour continuer...")

    # ==========================================================================
    # RESULTATS FINAUX
    # ==========================================================================

    clear_screen()
    print_header("RESULTATS")

    percentage = (score / total) * 100
    passed = score >= quiz['passing_score']

    # Affichage du score
    color = Colors.GREEN if passed else Colors.RED
    status = "REUSSI ✓" if passed else "ECHEC ✗"

    print(f"  Score: {color}{score}/{total} ({percentage:.0f}%){Colors.END}")
    print(f"  Statut: {color}{status}{Colors.END}")
    print()

    # Barre de progression visuelle
    bar_length = 30
    filled = int(bar_length * score / total)
    bar = '█' * filled + '░' * (bar_length - filled)
    print(f"  [{bar}]")
    print()

    # Questions ratees
    if wrong_answers:
        print(f"{Colors.YELLOW}  A reviser:{Colors.END}")
        print()
        for wa in wrong_answers:
            print(f"    Q{wa['num']}: {wa['question']}...")
        print()

    # Message final
    if passed:
        print(f"{Colors.GREEN}  🎉 Bravo ! Tu peux passer a la semaine suivante.{Colors.END}")
        print()
        print(f"  N'oublie pas de commit ta progression:")
        print(f"    git add . && git commit -m \"feat: semaine X complete\"")
    else:
        print(f"{Colors.YELLOW}  📚 Relis les lessons et reessaie.{Colors.END}")
        print()
        print(f"  Concentre-toi sur les questions ratees.")

    print()

    return passed, score

# =============================================================================
# SAUVEGARDE DES RESULTATS
# =============================================================================

def save_results(quiz_path: str, score: int, total: int, passed: bool):
    """Sauvegarde les resultats dans un fichier"""
    results_file = Path(quiz_path).parent / ".quiz_results"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "PASS" if passed else "FAIL"

    with open(results_file, 'a', encoding='utf-8') as f:
        f.write(f"{timestamp} | Score: {score}/{total} | {status}\n")

# =============================================================================
# MAIN
# =============================================================================

def main():
    init_colors()

    # Verifier les arguments
    if len(sys.argv) < 2:
        print()
        print(f"{Colors.BOLD}Quiz Runner - C Maldev Journey{Colors.END}")
        print()
        print("Usage:")
        print(f"  python {sys.argv[0]} <chemin/vers/quiz.json>")
        print()
        print("Exemple:")
        print(f"  python {sys.argv[0]} Learning-Path/Phase-1-Foundations/Week-01-C-Absolute-Basics/quiz.json")
        print()
        sys.exit(1)

    quiz_path = sys.argv[1]

    # Verifier que le fichier existe
    if not Path(quiz_path).exists():
        print(f"{Colors.RED}Erreur: {quiz_path} non trouve{Colors.END}")
        sys.exit(1)

    # Charger et executer le quiz
    try:
        quiz = load_quiz(quiz_path)
        passed, score = run_quiz(quiz)

        # Sauvegarder les resultats
        save_results(quiz_path, score, len(quiz['questions']), passed)

        # Code de sortie
        sys.exit(0 if passed else 1)

    except json.JSONDecodeError as e:
        print(f"{Colors.RED}Erreur: Le fichier quiz.json est mal forme{Colors.END}")
        print(f"  Details: {e}")
        sys.exit(1)
    except KeyError as e:
        print(f"{Colors.RED}Erreur: Cle manquante dans le quiz: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
