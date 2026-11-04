class SourceSkipped(Exception):
    """La source n'a pas pu être interrogée pour une raison attendue (clé absente, non applicable)."""


class SourceFailed(Exception):
    """La source a échoué : l'absence de résultat ne prouve rien."""
