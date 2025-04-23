import pytest
from core.resolver import detect_wildcard, generate_permutations

def test_detect_wildcard():
    assert detect_wildcard("example.com") == False  # Domínio sem wildcard
    # ... mais testes

def test_generate_permutations():
    base = ["www", "mail"]
    perms = generate_permutations(base)
    assert "www-dev" in perms
    assert "mail-prod" in perms
    assert len(perms) <= 100000  # Respeitando o limite