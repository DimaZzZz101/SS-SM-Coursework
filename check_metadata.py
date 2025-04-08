class CheckMetadata:
    """Класс-структура для сбора результатов проверок"""
    def __init__(self, result="", description="", fix=""):
        self.result = result
        self.description = description
        self.fix = fix