# 🛡️ Safe Code Manager

Un gestionnaire de mots de passe **local, sécurisé et open-source**, développé en Python avec une interface graphique moderne.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)

---

## ✨ Fonctionnalités

- 🔐 **Chiffrement Zero-Knowledge** (AES-256-GCM + PBKDF2 avec 600 000 itérations)
- 🎲 **Générateur de mots de passe** cryptographiquement sûr (module `secrets`)
- 📊 **Indicateur de force** en temps réel
- 🔍 **Recherche instantanée** dans tous les champs
- 📂 **Organisation par catégories** et notes
- ⚠️ **Détection des mots de passe dupliqués**
- ⏱️ **Verrouillage automatique** configurable (1 à 30 min, ou désactivé)
- 🔄 **Changement du mot de passe maître** avec re-chiffrement complet
- ✏️ **Modification** des entrées existantes
- 📋 **Copie sécurisée** avec effacement automatique du presse-papier (30s)
- 🌙 **Interface sombre** moderne (CustomTkinter)

---

## 🛠️ Installation

### Prérequis
- [Python 3.10 ou supérieur](https://www.python.org/downloads/)
- Windows 10/11

### 1. Cloner le projet
```bash
git clone https://github.com/TON_PSEUDO/safe-code-manager.git
cd safe-code-manager