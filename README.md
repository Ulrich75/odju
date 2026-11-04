# odju

Audit d'exposition numérique en console, assisté par IA. À partir d'un email ou d'un nom, odju indique où une identité est exposée, avec la source, la criticité et un pourcentage de confiance, puis explique comment corriger.

**Usage autorisé :** votre propre identité, ou celle d'une personne qui vous a donné son accord explicite. L'outil demande cette confirmation et la consigne localement. C'est une déclaration, pas une vérification technique.

## Installation

```bash
uv sync
uv run odju
```

Toutes les clés sont facultatives (voir `.env.example`) :

| Variable | Apport |
|---|---|
| `ANTHROPIC_API_KEY` | Recherche web, synthèse, plan d'action et correctifs personnalisés |
| `HIBP_API_KEY` | Source Have I Been Pwned (abonnement payant) |
| `GITHUB_TOKEN` | Quotas GitHub plus élevés |

## Commandes

```text
odju scan jean@exemple.fr          analyse un email
odju scan "Jean Dupont"            analyse un nom
odju list [--all] [--min eleve]    liste les constats
odju info F1                       détail de la faille et du risque
odju fix F1                        correctif recommandé
odju plan                          plan d'action priorisé
odju export rapport.md             exporte en Markdown ou JSON
odju                               ouvre le mode interactif
odju --no-ai scan ...              n'envoie rien à l'IA
```

En script, ajoutez `--consent self` ou `--consent authorized`.

## Lire les résultats

- **Criticité** : calculée par des règles fixes (`scoring.py`) selon les données exposées, jamais par l'IA.
- **Confiance (%)** : probabilité que le résultat concerne bien cette personne. Elle est élevée pour une correspondance exacte d'email, faible pour un nom (homonymes), et plafonnée à 85 % ou 70 % pour les pages web.
- **Score d'exposition (0-100)** : cumule les constats selon leur criticité et leur confiance.
- **Couverture** : odju ne peut pas voir « tout internet ». Il indique les sources interrogées. Si l'une a échoué, le rapport le signale : un résultat vide ne prouve pas l'absence d'exposition.

## Sources

| Source | Cible | Clé |
|---|---|---|
| XposedOrNot (fuites) | email | non |
| Have I Been Pwned (fuites) | email | oui |
| Gravatar (profil public) | email | non |
| GitHub (profils, commits) | email, nom | facultative |
| DNS (SPF, DMARC), domaines personnalisés | email | non |
| Recherche web par IA | email, nom | oui |

## Données personnelles

- L'email ou le nom est transmis aux services ci-dessus pour effectuer la recherche.
- Avec l'IA active, l'identité est envoyée à l'API Anthropic pour la recherche web. La synthèse et les correctifs ne reçoivent pas l'identité, seulement les constats.
- Sur le disque, le rapport ne contient que l'identité masquée (`~/.local/share/odju`, fichiers en 0600).
- Les valeurs exposées (mots de passe, numéros) ne sont jamais récupérées ni affichées : odju indique seulement le type de donnée.

## Tests

```bash
uv run pytest
```
