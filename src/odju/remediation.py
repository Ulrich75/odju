"""Base de correctifs hors ligne, utilisée avec ou sans IA."""

from __future__ import annotations

from dataclasses import dataclass

from odju.models import Finding


@dataclass(frozen=True)
class Advice:
    risk: str
    steps: tuple[str, ...]


ADVICE: dict[str, Advice] = {
    "password": Advice(
        "Un mot de passe divulgué permet de prendre le compte, et tout autre compte qui le réutilise.",
        (
            "Changez ce mot de passe sur le service concerné.",
            "Changez-le partout où vous l'avez réutilisé.",
            "Utilisez un gestionnaire de mots de passe (Bitwarden, KeePassXC…) avec un mot de passe unique par site.",
            "Activez la double authentification, de préférence par application ou clé de sécurité plutôt que par SMS.",
            "Vérifiez les sessions actives, appareils connectés et règles de transfert de votre messagerie.",
        ),
    ),
    "token": Advice(
        "Un jeton valide donne accès au compte sans mot de passe ni double authentification.",
        (
            "Déconnectez toutes les sessions du service pour invalider les jetons.",
            "Révoquez les applications tierces et clés d'API que vous ne reconnaissez pas.",
        ),
    ),
    "financial": Advice(
        "Ces données permettent des paiements frauduleux et des arnaques ciblées.",
        (
            "Contactez votre banque, faites opposition ou remplacez la carte si elle est encore valide.",
            "Contrôlez vos relevés des derniers mois et activez les alertes de transaction.",
            "Méfiez-vous des faux appels du « service fraude » : rappelez toujours le numéro officiel de la banque.",
        ),
    ),
    "identity": Advice(
        "Ces données facilitent l'usurpation d'identité (crédit, ouverture de compte, démarches).",
        (
            "Si une pièce d'identité est en cause, déclarez-le aux autorités compétentes de votre pays.",
            "Surveillez les ouvertures de comptes ou crédits à votre nom.",
            "Conservez les preuves de la fuite en cas de litige.",
        ),
    ),
    "contact": Advice(
        "Téléphone, adresse et date de naissance rendent les arnaques crédibles et servent à répondre aux questions de vérification.",
        (
            "Ne confirmez jamais vos informations lors d'un appel ou SMS non sollicité.",
            "Demandez à votre opérateur un code de protection contre le transfert de ligne (SIM swap).",
            "Changez les questions secrètes qui reposent sur ces données.",
        ),
    ),
    "phishing": Advice(
        "Votre adresse circule dans des listes utilisées pour le hameçonnage et le spam.",
        (
            "Vérifiez l'expéditeur et ne cliquez pas sur les liens reçus par email : passez par le site officiel.",
            "Supprimez les comptes que vous n'utilisez plus.",
            "Utilisez des alias d'email pour les nouvelles inscriptions.",
        ),
    ),
    "public_email": Advice(
        "Une adresse publique sur un profil est facile à collecter automatiquement.",
        (
            "Retirez l'email du profil, ou remplacez-le par une adresse dédiée.",
            "Vérifiez les autres champs publics : employeur, ville, liens.",
        ),
    ),
    "git_email": Advice(
        "L'email des commits reste visible dans l'historique public, même après modification du profil.",
        (
            "Activez « Keep my email addresses private » dans les paramètres GitHub.",
            "Configurez git avec l'adresse noreply fournie par GitHub : git config --global user.email ID+login@users.noreply.github.com",
            "Activez « Block command line pushes that expose my email ».",
            "Réécrire un historique existant (git filter-repo) casse les clones : réservez-le aux dépôts que vous maîtrisez.",
        ),
    ),
    "spf": Advice(
        "Sans SPF, rien n'indique quels serveurs peuvent envoyer des emails pour ce domaine.",
        (
            "Publiez un enregistrement TXT listant vos serveurs d'envoi, par exemple : v=spf1 include:_spf.votre-fournisseur.tld -all",
            "Testez l'envoi depuis tous vos outils avant de passer à -all.",
        ),
    ),
    "dmarc": Advice(
        "Sans DMARC appliqué, un tiers peut envoyer des emails qui semblent venir de votre domaine.",
        (
            "Publiez _dmarc.votre-domaine en TXT, en commençant par : v=DMARC1; p=none; rua=mailto:dmarc@votre-domaine",
            "Activez la signature DKIM chez votre fournisseur d'email.",
            "Analysez les rapports, puis passez progressivement à p=quarantine, puis p=reject.",
        ),
    ),
    "web_listing": Advice(
        "Une page publique reste indexée et peut être recoupée avec d'autres sources.",
        (
            "Modifiez ou supprimez l'information depuis votre compte si c'est possible.",
            "Sinon, contactez le site. Dans l'UE, le RGPD (article 17) permet de demander l'effacement.",
            "Demandez le déréférencement aux moteurs de recherche après suppression.",
        ),
    ),
    "homonym": Advice(
        "Ce résultat repose sur un nom : il peut concerner un homonyme.",
        ("Ouvrez la source et confirmez qu'il s'agit bien de vous avant d'agir.",),
    ),
}


def advice_for(finding: Finding) -> list[Advice]:
    return [ADVICE[tag] for tag in finding.tags if tag in ADVICE]
