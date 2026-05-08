"""
Agent 1 — Alert Investigation (Cerveau du système)
====================================================
Rôle    : Analyste stratégique — Context-Aware principal du système
Auteur  : Membre 1

Ce module contient la logique de décision pour l'investigation initiale 
et l'analyse de contexte historique.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Optional

import requests

# ─────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────
OLLAMA_URL   = os.getenv("OLLAMA_URL",   "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
PROMPT_PATH  = Path(__file__).parent.parent / "prompts" / "agent1_prompt.txt"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [Agent1] %(levelname)s — %(message)s",
)
logger = logging.getLogger("Agent1")


# ─────────────────────────────────────────────
# Utilitaires
# ─────────────────────────────────────────────

def _load_prompt_template() -> str:
    """Charge le template de prompt depuis le système de fichiers."""
    if not PROMPT_PATH.exists():
        raise FileNotFoundError(
            f"Template introuvable : {PROMPT_PATH}\n"
            "Vérifiez que prompts/agent1_prompt.txt est présent."
        )
    return PROMPT_PATH.read_text(encoding="utf-8")


def _call_ollama(prompt: str) -> str:
    """Envoie le prompt à Ollama et retourne le texte brut de la réponse."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,
            "num_predict": 1024,
        },
    }
    logger.info("Appel Ollama (modèle : %s)", OLLAMA_MODEL)
    try:
        resp = requests.post(f"{OLLAMA_URL}/api/generate", json=payload, timeout=300)
        resp.raise_for_status()
        return resp.json().get("response", "")
    except requests.exceptions.ConnectionError as exc:
        raise ConnectionError(
            f"Ollama inaccessible sur {OLLAMA_URL}. Lancez 'ollama serve'."
        ) from exc


def _parse_json_response(raw: str, label: str = "") -> dict:
    """Extrait et parse le JSON de la réponse Ollama en nettoyant le texte parasite."""
    # Nettoyage des balises Markdown et espaces
    cleaned = re.sub(r"```json", "", raw)
    cleaned = re.sub(r"```", "", cleaned)
    cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        logger.error("Erreur de parsing JSON pour %s : %s", label, exc)
        logger.error("Contenu brut reçu:\n%s", raw)
        raise ValueError(f"Réponse invalide de l'agent : {exc}") from exc


# ─────────────────────────────────────────────
# Fonctions principales du Round 1
# ─────────────────────────────────────────────

def run_round1(state: dict) -> dict:
    """
    Fonction principale du Round 1 : extraction des entités et questions initiales.
    Prend : state (dict contenant 'alert' et 'context_round1')
    Retourne : state mis à jour
    """
    alert = state.get("alert")
    if not alert:
        raise ValueError("Aucune alerte fournie dans le state pour le Round 1.")

    logger.info("Démarrage du Round 1 — Alert: %s", alert.get("rule", {}).get("description", "N/A"))

    # Charger le template
    try:
        prompt_template = _load_prompt_template()
    except FileNotFoundError:
        logger.error("Template non trouvé, arrêt du Round 1.")
        state.update({
            "entites_extraites": {},
            "questions_round1": [],
            "error": "Template introuvable"
        })
        return state

    # Construire le prompt
    context_hist = state.get("context_round1", [])
    prompt = prompt_template.format(
        alert=json.dumps(alert, indent=2, ensure_ascii=False),
        context_round1=json.dumps(context_hist, indent=2, ensure_ascii=False),
        mode="ROUND1_QUESTIONS"
    )

    # Appel Ollama
    try:
        raw_response = _call_ollama(prompt)
        data = _parse_json_response(raw_response, label="Round 1")
    except Exception as exc:
        logger.error("Erreur critique Round 1 : %s", exc)
        state.update({
            "entites_extraites": {},
            "questions_round1": [],
            "error": str(exc)
        })
        return state

    # Stocker les résultats dans le state
    state["entites_extraites"] = data.get("entites_extraites", {})
    state["questions_round1"] = data.get("questions_round1", [])

    logger.info("✓ Entités extraites: %s", list(state["entites_extraites"].keys()))
    logger.info("✓ %d questions générées pour le Round 2", len(state["questions_round1"]))

    return state


def run_analyse_contexte(state: dict) -> dict:
    """
    Fonction d'analyse de contexte après récupération des données du Round 2.
    Prend : state (contenant 'alert', 'context_round1', 'context_round2')
    Retourne : state mis à jour avec conclusion, questions R2 et résumé
    """
    alert = state.get("alert")
    context_r1 = state.get("context_round1") or []
    context_r2 = state.get("context_round2") or []

    if not alert:
        raise ValueError("Aucune alerte fournie dans le state pour Analyse Contexte.")

    logger.info("Démarrage de l'Analyse de Contexte (Round 2)")

    # Charger le template
    try:
        prompt_template = _load_prompt_template()
    except FileNotFoundError:
        logger.error("Template introuvable, arrêt de l'analyse.")
        state.update({
            "pattern_detecte": "ERROR",
            "conclusion_round1": "ERROR",
            "round2_required": False,
            "justification": "Template introuvable",
            "context_summary": "",
            "questions_round2": []
        })
        return state

    # Construire le prompt pour analyse de contexte
    prompt = prompt_template.format(
        alert=json.dumps(alert, indent=2, ensure_ascii=False),
        context_round1=json.dumps(context_r1, indent=2, ensure_ascii=False),
        mode="ANALYSE_CONTEXTE"
    )

    # Appel Ollama
    try:
        raw_response = _call_ollama(prompt)
        data = _parse_json_response(raw_response, label="Analyse Contexte")
    except Exception as exc:
        logger.error("Erreur analyse contexte : %s", exc)
        state.update({
            "pattern_detecte": "ERROR",
            "conclusion_round1": "ERROR",
            "round2_required": False,
            "justification": str(exc),
            "context_summary": "",
            "questions_round2": []
        })
        return state

    # Stocker dans le state
    state["pattern_detecte"] = data.get("pattern_detecte", "")
    state["conclusion_round1"] = data.get("conclusion_round1", "")
    state["round2_required"] = data.get("round2_required", True)
    state["justification"] = data.get("justification", "")
    state["context_summary"] = data.get("context_summary", "")
    state["questions_round2"] = data.get("questions_round2", [])

    logger.info("✓ Pattern détecté : %s", state["pattern_detecte"])
    logger.info("✓ Conclusion : %s", state["conclusion_round1"])
    logger.info("✓ Round 2 requis : %s", state["round2_required"])

    return state